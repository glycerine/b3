package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	cristalbase64 "github.com/cristalhq/base64"
	"lukechampine.com/blake3"
)

type Blake3SummerConfig struct {
	help bool
	All  bool

	nosym   bool
	quiet   bool
	recurse bool
	version bool
	paths   []string
}

func (c *Blake3SummerConfig) SetFlags(fs *flag.FlagSet) {

	fs.BoolVar(&c.nosym, "nosym", false, "do not follow symlinks")
	fs.BoolVar(&c.quiet, "q", false, "act quietly. do not complain if no files to scan")
	fs.BoolVar(&c.help, "help", false, "show this help")
	fs.BoolVar(&c.recurse, "r", false, "recursive checksum sub-directories")
	fs.BoolVar(&c.All, "all", false, "include emacs temp files ending in ~ (ignored by default)")
	fs.BoolVar(&c.version, "version", false, "show version of b3/dependencies")
}

func (c *Blake3SummerConfig) FinishConfig(fs *flag.FlagSet) (err error) {

	// everything else -- not behind a flag -- is a target path to checksum
	c.paths = fs.Args()

	if len(c.paths) == 0 {
		return fmt.Errorf("no paths to process")
	}
	return nil
}

func usageB3(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `
b3 computes the blake3 cryptographic hash (a checksum)

Targets are specified by their filenames/paths without
any special flag.

Flags:
`)
	fs.PrintDefaults()
	os.Exit(1)
}

// b3 calls
func main() {
	//vv("top of main for b3")
	Exit1IfVersionReq()

	cfg := &Blake3SummerConfig{}
	fs := flag.NewFlagSet("b3", flag.ExitOnError)
	cfg.SetFlags(fs)
	fs.Parse(os.Args[1:])
	err := cfg.FinishConfig(fs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "b3 error: command line problem: '%s'\n", err)
		os.Exit(1)
	}
	if cfg.help {
		fs.PrintDefaults()
		return
	}

	//vv("cfg.paths = '%#v'", cfg.paths)

	var paths []string

	// process globs / patterns
	for _, path := range cfg.paths {
		// syntax is the same as filepath.Match()
		// https://pkg.go.dev/path/filepath#Match
		matches, err := filepath.Glob(path)
		panicOn(err)
		paths = append(paths, matches...)
	}

	if !cfg.recurse {

		sort.Strings(paths)
		//vv("paths = '%#v'", paths)
		did := 0
		for _, path := range paths {

			fi, err := os.Stat(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "b3 error on stat of target path '%v': '%v'", path, err)
				continue
			}
			if fi.IsDir() {
				// ignore directories
				continue
			} else if !cfg.All && strings.HasSuffix(path, "~") {
				continue
			} else {
				sum, err := Blake3OfFile(path)
				panicOn(err)
				fmt.Printf("%v   %v\n", sum, path)
				did++
			}
		}

		if did == 0 && !cfg.quiet {
			fmt.Fprintf(os.Stderr, "b3 error: no files to scan. Did you want -r to recurse? Use -q to suppress this warning.\n")
			os.Exit(1)
		}
	} else {
		// -r implementation of recursive.

		// paths has top level files.
		// get files from dirs too.
		var dirs []string

		fileMap := make(map[string]bool)

		// get dirs
		for _, path := range paths {

			fi, err := os.Stat(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "b3 error on stat of target path '%v': '%v'", path, err)
				continue
			}
			if fi.IsDir() {
				if path == "." || path == ".." {
					// don't scan above, or ourselves again.
				} else {
					dirs = append(dirs, path)
				}
			} else {
				fileMap[path] = true
			}
		}

		// fill in the fileMap with all files in a recursive directory walk
		cfg.WalkDirs(dirs, fileMap)
		// don't scan ..
		delete(fileMap, "..")
		delete(fileMap, ".")

		// path -> blake3 checksum
		results := make(chan *pathsum, 100000)

		// checksum the files in parallel.
		cfg.ScanFiles(fileMap, results)

		var sums pathsumSlice // []*pathsum
		for sum := range results {
			sums = append(sums, sum)
		}

		// report in lexicographic order
		sort.Sort(sums)
		for _, s := range sums {
			fmt.Printf("%v   %v\n", s.sum, s.path)
		}
	}
}

type pathsum struct {
	path string
	sum  string
}

type pathsumSlice []*pathsum

func (p pathsumSlice) Len() int { return len(p) }
func (p pathsumSlice) Less(i, j int) bool {
	return p[i].path < p[j].path
}
func (p pathsumSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

func Blake3OfFile(path string) (blake3sum string, err error) {
	fd, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fd.Close()
	h := blake3.New(64, nil)
	io.Copy(h, fd)
	by := h.Sum(nil)

	blake3sum = "blake3.32B-" + cristalbase64.URLEncoding.EncodeToString(by[:32])
	return
}

func (cfg *Blake3SummerConfig) WalkDirs(dirs []string, files map[string]bool) {

	for _, dir := range dirs {
		cfg.ScanOneDir(dir, files)
	}
	return
}

func (cfg *Blake3SummerConfig) ScanOneDir(root string, files map[string]bool) {
	if !dirExists(root) {
		return
	}

	err := cfg.walkFollowSymlink(root, func(path string, info os.FileInfo, err error) error {
		// if there was a filesystem error reading one of our dir, we want to know.
		panicOn(err)
		//vv("WalkDir found path = '%v'", path)
		if info != nil && !IsNil(info) {
			if info.IsDir() {
				if strings.HasPrefix(path, "_") { // || strings.HasPrefix(path, ".") {
					//vv("skipping _ file")
					return filepath.SkipDir
				}
			} else {
				if strings.HasPrefix(path, "_") { // || strings.HasPrefix(path, ".") {
					return nil
				}
				//vv("good path '%v' found!", path)
				files[path] = true
			}
		}
		return nil
	})
	panicOn(err)
}

func (cfg *Blake3SummerConfig) ScanFiles(files map[string]bool, results chan *pathsum) {
	var wg sync.WaitGroup
	wg.Add(len(files))

	ngoro := runtime.NumCPU()

	work := make(chan string, 1024)
	for i := 0; i < ngoro; i++ {
		go func() {
			for path := range work {
				err := cfg.ScanOneFile(path, results)
				wg.Done()
				if err != nil {
					alwaysPrintf("error on path '%v': '%v'", path, err)
				}
			}
		}()
	}

	for path := range files {
		work <- path
	}
	wg.Wait()
	close(results)
}

func (cfg *Blake3SummerConfig) ScanOneFile(path string, results chan *pathsum) (err error) {

	sum, err := Blake3OfFile(path)
	if err != nil {
		return nil
	}

	results <- &pathsum{path: path, sum: sum}
	return
}

// from path/filepath/path.go, but modified to FOLLOW symlinks
// WalkFollowSymlink walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root. All errors that arise visiting files
// and directories are filtered by walkFn. The files are walked in lexical
// order, which makes the output deterministic but means that for very
// large directories Walk can be inefficient.
// This Walk *does* follow symbolic links.
func (cfg *Blake3SummerConfig) walkFollowSymlink(root string, walkFn filepath.WalkFunc) error {

	var info os.FileInfo
	var err error

	if cfg.nosym {
		info, err = os.Lstat(root) // does not follow sym links
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
	} else {
		info, err = os.Stat(root)
	}

	if err != nil {
		err = walkFn(root, nil, err)
	} else {
		err = cfg.walk(root, info, walkFn)
	}
	if err == filepath.SkipDir {
		return nil
	}
	return err
}

// also from path/filepath/path.go
// walk recursively descends path, calling walkFn.
func (cfg *Blake3SummerConfig) walk(path string, info os.FileInfo, walkFn filepath.WalkFunc) error {
	if !info.IsDir() {
		return walkFn(path, info, nil)
	}

	names, err := readDirNames(path)
	err1 := walkFn(path, info, err)
	// If err != nil, walk can't walk into this directory.
	// err1 != nil means walkFn want walk to skip this directory or stop walking.
	// Therefore, if one of err and err1 isn't nil, walk will return.
	if err != nil || err1 != nil {
		// The caller's behavior is controlled by the return value, which is decided
		// by walkFn. walkFn may ignore err and return nil.
		// If walkFn returns SkipDir, it will be handled by the caller.
		// So walk should return whatever walkFn returns.
		return err1
	}

	for _, name := range names {
		filename := filepath.Join(path, name)
		var fileInfo os.FileInfo
		var err error
		if cfg.nosym {
			fileInfo, err = os.Lstat(filename) // does not follow sym links
			if fileInfo.Mode()&os.ModeSymlink != 0 {
				continue
			}
		} else {
			fileInfo, err = os.Stat(filename) // instead of os.Lstat, follows symlinks
		}
		if err != nil {
			if err := walkFn(filename, fileInfo, err); err != nil && err != filepath.SkipDir {
				return err
			}
		} else {
			err = cfg.walk(filename, fileInfo, walkFn)
			if err != nil {
				if !fileInfo.IsDir() || err != filepath.SkipDir {
					return err
				}
			}
		}
	}
	return nil
}

// also from path/filepath/path.go, used by the above.
// readDirNames reads the directory named by dirname and returns
// a list of directory entries.
func readDirNames(dirname string) ([]string, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	return names, nil
}
