package main

import (
	"bufio"
	"flag"
	"fmt"
	iofs "io/fs"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	cristalbase64 "github.com/cristalhq/base64"
	"github.com/glycerine/blake3"
)

const fRFC3339NanoNumericTZ0pad = "2006-01-02T15:04:05.000000000-07:00"

type Blake3SummerConfig struct {
	help bool

	maxDepth int
	nosym    bool

	recurse bool
	version bool

	globs []string

	hasExcludes bool
	xprefix     excludes
	xsuffix     excludes

	pathListStdin bool

	modtimeHash bool

	// output hex string for comparison with other tools?
	hex bool

	// skip directory walking.
	singleFilePath string

	// output paths before hashes, for easier sorting/diffs
	pathsFirst bool
}

type excludes struct {
	x []string
}

func (tf *excludes) String() string {
	s := ""
	for _, ta := range tf.x {
		s += ta + ","
	}
	return s
}

// the flags package will call Set(),
// in command line order, once for each "-x" or "-xs" flag present.
func (tf *excludes) Set(value string) error {
	//vv("Set called with value = '%v'", value)
	splt := strings.Split(value, ",")
	for _, s := range splt {
		ss := strings.TrimSpace(s)
		//if ss != "" {
		tf.x = append(tf.x, ss)
		//}
	}
	return nil
}

func (c *Blake3SummerConfig) SetFlags(fs *flag.FlagSet) {

	fs.BoolVar(&c.pathListStdin, "i", false, "read list of paths on stdin")
	fs.BoolVar(&c.nosym, "nosym", false, "do not follow symlinked directories")

	fs.BoolVar(&c.help, "help", false, "show this help")
	fs.BoolVar(&c.recurse, "r", false, "recursive checksum sub-directories")
	fs.BoolVar(&c.version, "version", false, "show version of b3/dependencies")

	fs.Var(&c.xprefix, "x", "file name prefix to exclude (multiple -x okay; default: '_')")
	fs.Var(&c.xsuffix, "xs", "file name suffix to exclude (multiple -xs okay; default: '~')")

	fs.BoolVar(&c.modtimeHash, "mt", false, "include modtime in the hash")

	fs.BoolVar(&c.hex, "hex", false, "output as hex rather than base64")

	fs.StringVar(&c.singleFilePath, "f", "", "just sum this single file, no directory walking.")
	fs.BoolVar(&c.pathsFirst, "s", false, "sortable, so path names first then hashes in output")
}

func (cfg *Blake3SummerConfig) FinishConfig(fs *flag.FlagSet) (err error) {

	// everything else -- not behind a flag -- is a target path to checksum
	cfg.globs = fs.Args()

	//vv("cfg.xsuffix = '%#v'", cfg.xsuffix)
	//vv("cfg.xprefix = '%#v'", cfg.xprefix)

	// allow user to omit all excludes with -x='' -xs=''
	if len(cfg.xsuffix.x) == 1 && cfg.xsuffix.x[0] == "" {
		cfg.xsuffix.x = nil
	} else if len(cfg.xsuffix.x) == 0 {
		cfg.xsuffix.x = []string{"~"}
	}

	if len(cfg.xprefix.x) == 1 && cfg.xprefix.x[0] == "" {
		cfg.xprefix.x = nil
	} else if len(cfg.xprefix.x) == 0 {
		cfg.xprefix.x = []string{"_"}
	}

	cfg.hasExcludes = len(cfg.xprefix.x) > 0 || len(cfg.xsuffix.x) > 0
	//vv("cfg.hasExcludes = %v", cfg.hasExcludes)

	if len(cfg.globs) == 0 {
		// default to the current directory
		cfg.globs = []string{"*"}
		//return fmt.Errorf("no globs to process")
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

	//vv("cfg.globs = '%#v'", cfg.globs)

	//vv("cfg.xsuffix = '%#v'", cfg.xsuffix)
	//vv("cfg.xprefix = '%#v'", cfg.xprefix)

	// path -> blake3 checksum
	results := make(chan *pathsum, 100000)

	fileMap := make(map[string]bool)
	var paths []string

	if cfg.singleFilePath != "" {
		t0 := time.Now()
		sum, err := cfg.Blake3OfFile(cfg.singleFilePath)
		elap := time.Since(t0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "b3 error on path '%v': %v\n", cfg.singleFilePath, err)
			os.Exit(1)
		}
		if cfg.pathsFirst {
			fmt.Printf("%v   %v\n", cfg.singleFilePath, sum)
		} else {
			fmt.Printf("%v   %v\n", sum, cfg.singleFilePath)
		}
		fi, err := os.Stat(cfg.singleFilePath)
		panicOn(err)
		sz := float64(fi.Size()) / (1 << 20) // in MB/sec
		fmt.Printf("%0.3f MB.  elap = %v. rate =   %0.6f  MB/sec\n", sz, elap, sz/(float64(elap)/1e9))
		os.Exit(0)
	}

	if cfg.pathListStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			//fmt.Println("Got line:", line)

			fi, err := os.Stat(line)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				if cfg.hasExcludes && cfg.shouldExclude(line) {
					//vv("skipping line '%v'", line)
				} else {
					fileMap[line] = true
				}
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "b3 error reading standard input: %v\n", err)
		}

	} else {

		if !cfg.recurse {
			cfg.maxDepth = 1
		}

		// paths has top level files.
		// get files from dirs too.
		var dirs []string

		// get dirs; all of them so we look for our pattern below the cwd.

		for _, g := range cfg.globs {
			d := filepath.Dir(g)
			//vv("d = '%v'", d)
			var pre string
			if d != "." {
				pre = d + "/"
			}
			entries, err := os.ReadDir(d)
			panicOn(err)
			for _, entry := range entries {
				if entry.Type()&iofs.ModeSymlink != 0 {
					if cfg.nosym {
						continue
					}
				}
				if entry.IsDir() {
					dirs = append(dirs, pre+entry.Name())
				} else {
					paths = append(paths, pre+entry.Name())
				}
			}
		}

		for _, path := range paths {
			//vv("path = '%v'", path)
			//fi, err := os.Stat(path) // symlink dangling targets -> error
			fi, err := os.Lstat(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "b3 error on Lstat of target path '%v': '%v'\n", path, err)
				continue
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				if cfg.nosym {
					// fall through, do not chase symlinks
				} else {
					target, err := os.Readlink(path)
					if err == nil {
						fi2, err := os.Stat(target)
						if err != nil {
							// now allow dangling link, since they
							// can be backed up too.
							//fmt.Fprintf(os.Stderr, "b3 allowing dangling link '%v'\n", path)
							// old approach:
							//fmt.Fprintf(os.Stderr, "b3 error on stat of symlink target path '%v': '%v'\n", path, err)
							//continue
						} else {
							fi = fi2
							path = target
						}
					} else {
						// allow dangling links
						fmt.Fprintf(os.Stderr, "b3 allowing dangling link '%v'; Readlink err = '%v'\n", path, err)
					}
				}
			}

			if fi.IsDir() {
				if path == "." || path == ".." {
					//if path == ".." {
					// don't scan above
				} else {
					dirs = append(dirs, path)
				}
			} else {
				if cfg.keep(path) {
					fileMap[path] = true
				}
			}
		}
		//vv("dirs = '%#v'", dirs)

		// fill in the fileMap with all files in a recursive directory walk
		cfg.WalkDirs(dirs, fileMap)

	}
	// don't scan ..
	delete(fileMap, "..")
	delete(fileMap, ".")

	// checksum the files in parallel.
	cfg.ScanFiles(fileMap, results)

	var sums pathsumSlice // []*pathsum
	for sum := range results {
		sums = append(sums, sum)
	}

	// over-all hash of hashes
	hoh := blake3.New(64, nil)

	// report in lexicographic order
	sort.Sort(sums)
	for _, s := range sums {
		if cfg.pathsFirst {
			fmt.Printf("%v   %v\n", s.path, s.sum)
		} else {
			fmt.Printf("%v   %v\n", s.sum, s.path)
		}
		hoh.Write([]byte(s.sum))
	}

	if len(sums) > 1 {
		by := hoh.Sum(nil)
		allsum := "blake3.33B-" + cristalbase64.URLEncoding.EncodeToString(by[:33])
		if cfg.hex {
			allsum = fmt.Sprintf("%x", by[:32])
		}

		fmt.Printf("%v   [hash of hashes; checksum of above]\n", allsum)
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

func (cfg *Blake3SummerConfig) Blake3OfFile(path string) (blake3sum string, err error) {

	var sum []byte
	var h *blake3.Hasher

	done := false
	fi, err := os.Lstat(path)
	panicOn(err)
	isSymlink := fi.Mode()&os.ModeSymlink != 0

	if isSymlink {
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		if cfg.nosym || !fileExists(target) {
			done = true

			// Under -nosym, if we find a symlink,
			// we just use the target path as the data to hash.
			h = blake3.New(64, nil)
			h.Write([]byte(target))
			sum = h.Sum(nil)

			if cfg.modtimeHash {
				s := fmt.Sprintf("%v",
					fi.ModTime().UTC().Format(fRFC3339NanoNumericTZ0pad))
				h.Write([]byte(s))
				sum = h.Sum(nil)
			}
		} else {
			vv("have sym link path '%v', target '%v'", path, target)
		}
	}
	if !done {

		// use the new HashFile() facility.
		sum, h, err = blake3.HashFile(path)
		if err != nil {
			//vv("blake3.HashFile gave error: '%v'", err) // no such file
			return "", err
		}

		if cfg.modtimeHash {
			fi, err := os.Stat(path)
			if err != nil {
				return "", err
			}
			// put into a canonical format.
			s := fmt.Sprintf("%v", fi.ModTime().UTC().Format(fRFC3339NanoNumericTZ0pad))
			h.Write([]byte(s))
			sum = h.Sum(nil)
		}
	}
	if cfg.hex {
		blake3sum = fmt.Sprintf("%x", sum[:32])
	} else {
		blake3sum = "blake3.33B-" + cristalbase64.URLEncoding.EncodeToString(sum[:33])
	}
	return
}

func (cfg *Blake3SummerConfig) shouldExclude(path string) bool {
	base := filepath.Base(path)

	for _, xpre := range cfg.xprefix.x {
		if strings.HasPrefix(base, xpre) {
			return true
		}
	}
	for _, xsuf := range cfg.xsuffix.x {
		if strings.HasSuffix(base, xsuf) {
			return true
		}
	}
	if path != base {
		for _, xpre := range cfg.xprefix.x {
			if strings.HasPrefix(path, xpre) {
				return true
			}
		}
		for _, xsuf := range cfg.xsuffix.x {
			if strings.HasSuffix(path, xsuf) {
				return true
			}
		}
	}
	return false
}

func (cfg *Blake3SummerConfig) keep(path string) bool {

	if cfg.hasExcludes && cfg.shouldExclude(path) {
		return false
	}
	for _, glob := range cfg.globs {
		if glob == "*" {
			return true
		}
		if strings.Contains(path, glob) {
			return true
		}
	}
	return false
}

func (cfg *Blake3SummerConfig) WalkDirs(dirs []string, files map[string]bool) {

	for _, dir := range dirs {
		cfg.ScanOneDir(dir, files)
	}
	return
}

func (cfg *Blake3SummerConfig) ScanOneDir(root string, files map[string]bool) {
	//vv("ScanOneDir root='%v'", root)
	if !dirExists(root) {
		return
	}
	di := NewDirIter()
	di.FollowSymlinks = !cfg.nosym
	next, stop := iter.Pull2(di.FilesOnly(root))
	defer stop()

	for {
		path, ok, valid := next()
		if !valid {
			break
		}
		if !ok {
			break
		}
		if cfg.hasExcludes && cfg.shouldExclude(path) {

		} else {
			// process globs / patterns
			if cfg.keep(path) {
				files[path] = true
			}
		}
	}
}

func (cfg *Blake3SummerConfig) oldScanOneDir(root string, files map[string]bool) {
	vv("ScanOneDir root='%v'", root)
	if !dirExists(root) {
		return
	}

	err := cfg.walkFollowSymlink(root, func(path string, info os.FileInfo, depth int, err error) error {
		// if there was a filesystem error reading one of our dir, we want to know.
		panicOn(err)

		if info != nil && !IsNil(info) {

			//vv("WalkDir found path = '%v' base = '%v'", path, info.Name())

			//base := info.Name()
			isDir := info.IsDir()
			if cfg.hasExcludes && cfg.shouldExclude(path) {

				if isDir {
					return filepath.SkipDir
				}
				return nil
			}

			if !isDir {
				// process globs / patterns
				if cfg.keep(path) {
					files[path] = true
				}
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

	sum, err := cfg.Blake3OfFile(path)
	if err != nil {
		return nil
	}

	results <- &pathsum{path: path, sum: sum}
	return
}

type depthWalkFunc func(path string, info os.FileInfo, depth int, err error) error

// from path/filepath/path.go, but modified to FOLLOW symlinks
// WalkFollowSymlink walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root. All errors that arise visiting files
// and directories are filtered by walkFn. The files are walked in lexical
// order, which makes the output deterministic but means that for very
// large directories Walk can be inefficient.
// This Walk *does* follow symbolic links.
func (cfg *Blake3SummerConfig) walkFollowSymlink(root string, walkFn depthWalkFunc) error {

	var info os.FileInfo
	var err error

	if cfg.nosym {
		info, err = os.Lstat(root) // does not follow sym links
		if info.Mode()&os.ModeSymlink != 0 {
			//return nil
			//I think we do want to return the symlinks though:
			return walkFn(root, nil, 0, nil)
		}
	} else {
		info, err = os.Stat(root)
	}

	if err != nil {
		err = walkFn(root, nil, 0, err)
	} else {
		err = cfg.walk(0, root, info, walkFn)
	}
	if err == filepath.SkipDir {
		return nil
	}
	return err
}

// also from path/filepath/path.go
// walk recursively descends path, calling walkFn.
func (cfg *Blake3SummerConfig) walk(depth int, path string, info os.FileInfo, walkFn depthWalkFunc) error {

	if cfg.maxDepth > 0 && depth >= cfg.maxDepth {
		vv("hit maxDepth at %v.  path = '%v'", depth, path)
		return filepath.SkipDir
	} else {
		//vv("depth(%v) <= maxDepth at %v.  path = '%v'", depth, cfg.maxDepth, path)
	}

	if !info.IsDir() {
		return walkFn(path, info, depth, nil)
	}
	//vv("walk in path '%v'", path)

	names, err := readDirNames(path)
	err1 := walkFn(path, info, depth, err)
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
			if err := walkFn(filename, fileInfo, depth, err); err != nil && err != filepath.SkipDir {
				return err
			}
		} else {
			err = cfg.walk(depth+1, filename, fileInfo, walkFn)
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
