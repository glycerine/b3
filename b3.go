package b3

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
	Help bool

	MaxDepth int

	// we default to NOT following symlinks now.
	FollowSymLinks bool

	Recurse bool
	Version bool

	Globs []string

	HasExcludes bool
	Xprefix     excludes
	Xsuffix     excludes

	PathListStdin bool

	ModTimeHash bool

	// output hex string for comparison with other tools?
	Hex bool

	// skip directory walking.
	SingleFilePath string

	// output paths before hashes, for easier sorting/diffs
	PathsFirst bool

	Quiet bool
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

	fs.BoolVar(&c.PathListStdin, "i", false, "read list of paths on stdin")
	//fs.BoolVar(&c.FollowSymLinks, "followsym", false, "follow symlinked directories")

	fs.BoolVar(&c.Help, "help", false, "show this help")
	fs.BoolVar(&c.Recurse, "r", false, "recursive checksum sub-directories")
	fs.BoolVar(&c.Version, "version", false, "show version of b3/dependencies")

	fs.Var(&c.Xprefix, "x", "file name prefix to exclude (multiple -x okay; default: '_')")
	fs.Var(&c.Xsuffix, "xs", "file name suffix to exclude (multiple -xs okay; default: '~')")

	fs.BoolVar(&c.ModTimeHash, "mt", false, "include modtime in the hash")

	fs.BoolVar(&c.Hex, "hex", false, "output as hex rather than base64")

	fs.StringVar(&c.SingleFilePath, "f", "", "just sum this single file, no directory walking.")
	fs.BoolVar(&c.PathsFirst, "s", false, "sortable, so path names first then hashes in output")
}

func (cfg *Blake3SummerConfig) FinishConfig(fs *flag.FlagSet) (err error) {

	// everything else -- not behind a flag -- is a target path to checksum
	cfg.Globs = fs.Args()

	//vv("cfg.Xsuffix = '%#v'", cfg.Xsuffix)
	//vv("cfg.Xprefix = '%#v'", cfg.Xprefix)

	// allow user to omit all excludes with -x='' -xs=''
	if len(cfg.Xsuffix.x) == 1 && cfg.Xsuffix.x[0] == "" {
		cfg.Xsuffix.x = nil
	} else if len(cfg.Xsuffix.x) == 0 {
		cfg.Xsuffix.x = []string{"~"}
	}

	if len(cfg.Xprefix.x) == 1 && cfg.Xprefix.x[0] == "" {
		cfg.Xprefix.x = nil
	} else if len(cfg.Xprefix.x) == 0 {
		cfg.Xprefix.x = []string{"_"}
	}

	cfg.HasExcludes = len(cfg.Xprefix.x) > 0 || len(cfg.Xsuffix.x) > 0
	//vv("cfg.HasExcludes = %v", cfg.HasExcludes)

	if len(cfg.Globs) == 0 {
		// default to the current directory
		cfg.Globs = []string{"*"}
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
func Main() {
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
	if cfg.Help {
		fs.PrintDefaults()
		return
	}

	_, err = DirTreeBlake3Hash(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

type DirTreeHash struct {
	// response if cfg.SingleFilePath != "" is
	// in SinglePath and TopBlake3
	SinglePath string

	// for multiple files, TopBlake3 has the root hash,
	// a hash of all of these hashes after sorting.
	PathSums []*PathSum

	// TopBlake3 holds the blake3 hash of the SinglePath file, or the hash
	// of the sorted hashs of PathSums.
	TopBlake3 string
}

func DirTreeBlake3Hash(cfg *Blake3SummerConfig) (ret *DirTreeHash, err0 error) {

	ret = &DirTreeHash{}

	//vv("cfg.Globs = '%#v'", cfg.Globs)

	//vv("cfg.Xsuffix = '%#v'", cfg.Xsuffix)
	//vv("cfg.Xprefix = '%#v'", cfg.Xprefix)

	// path -> blake3 checksum
	results := make(chan *PathSum, 100000)

	fileMap := make(map[string]bool)
	var paths []string

	if cfg.SingleFilePath != "" {
		t0 := time.Now()
		sum, err := cfg.Blake3OfFile(cfg.SingleFilePath)
		elap := time.Since(t0)
		if err != nil {
			return nil, fmt.Errorf("b3 error on path '%v': %v\n", cfg.SingleFilePath, err)
		}
		if !cfg.Quiet {
			if cfg.PathsFirst {
				fmt.Printf("%v   %v\n", cfg.SingleFilePath, sum)
			} else {
				fmt.Printf("%v   %v\n", sum, cfg.SingleFilePath)
			}

			fi, err := os.Stat(cfg.SingleFilePath)
			panicOn(err)
			sz := float64(fi.Size()) / (1 << 20) // in MB/sec
			fmt.Printf("%0.3f MB.  elap = %v. rate =   %0.6f  MB/sec\n", sz, elap, sz/(float64(elap)/1e9))
		}
		ret.SinglePath = cfg.SingleFilePath
		ret.TopBlake3 = sum
		return
	}

	if cfg.PathListStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			//fmt.Println("Got line:", line)

			fi, err := os.Stat(line)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				if cfg.HasExcludes && cfg.shouldExclude(line) {
					//vv("skipping line '%v'", line)
				} else {
					fileMap[line] = true
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("b3 error reading standard input: %v\n", err)
		}

	} else {

		if !cfg.Recurse {
			cfg.MaxDepth = 1
		}

		// paths has top level files.
		// get files from dirs too.
		var dirs []string

		// get dirs; all of them so we look for our pattern below the cwd.

		for _, g := range cfg.Globs {
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
					if !cfg.FollowSymLinks && entry.IsDir() {
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

				return nil, fmt.Errorf("b3 error on Lstat of target path '%v': '%v'\n", path, err)
			}
			//isSymlink := fi.Mode()&os.ModeSymlink != 0

			if false { // symlink stuff off for the moment
				if fi.Mode()&os.ModeSymlink != 0 {
					if !cfg.FollowSymLinks {
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

	var sums pathsumSlice // []*PathSum
	for sum := range results {
		sums = append(sums, sum)
	}

	// over-all hash of hashes
	hoh := blake3.New(64, nil)

	// report in lexicographic order
	sort.Sort(sums)

	ret.PathSums = sums

	for _, s := range sums {
		if !cfg.Quiet {
			if cfg.PathsFirst {
				fmt.Printf("%v   %v\n", s.Path, s.Sum)
			} else {
				fmt.Printf("%v   %v\n", s.Sum, s.Path)
			}
		}
		hoh.Write([]byte(s.Sum))
	}

	by := hoh.Sum(nil)
	allsum := "blake3.33B-" + cristalbase64.URLEncoding.EncodeToString(by[:33])
	if cfg.Hex {
		allsum = fmt.Sprintf("%x", by[:32])
	}
	ret.TopBlake3 = allsum

	if !cfg.Quiet {
		if len(sums) > 1 {
			fmt.Printf("%v   [hash of hashes; checksum of above]\n", allsum)
		}
	}
	return
}

type PathSum struct {
	Path string
	Sum  string
}

type pathsumSlice []*PathSum

func (p pathsumSlice) Len() int { return len(p) }
func (p pathsumSlice) Less(i, j int) bool {
	return p[i].Path < p[j].Path
}
func (p pathsumSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

func (cfg *Blake3SummerConfig) Blake3OfFile(path string) (blake3sum string, err error) {

	var sum []byte
	var h *blake3.Hasher

	done := false
	fi, err := os.Lstat(path)
	panicOn(err)
	isSymlink := fi.Mode()&os.ModeSymlink != 0

	// Symlinks that dangle or not make a mess
	// of our hashing and comparing directories.
	// We need a consistent approach to verify
	// that a mirroring of a filesystem tree has
	// happened. So lets never follow symlinks,
	// and always hash their target paths as the data.
	if isSymlink {
		done = true

		// We simply use the target path as the data to hash.
		// This verifies that a link got synced correctly.
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		h = blake3.New(64, nil)
		h.Write([]byte(target))
		sum = h.Sum(nil)

		if cfg.ModTimeHash {
			modTime := fi.ModTime()

			// ability to recreate timestamps on symlinks
			// to resolution past milliseconds is
			// just not there, so truncate our hash
			// to milliseconds too.
			modTime = modTime.Truncate(time.Millisecond)

			s := fmt.Sprintf("%v",
				modTime.UTC().Format(fRFC3339NanoNumericTZ0pad))
			h.Write([]byte(s))
			sum = h.Sum(nil)
		}
	}
	if !done {

		// use the new HashFile() facility.
		sum, h, err = blake3.HashFile(path)
		if err != nil {
			//vv("blake3.HashFile gave error: '%v'", err) // no such file
			return "", err
		}

		if cfg.ModTimeHash {
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
	if cfg.Hex {
		blake3sum = fmt.Sprintf("%x", sum[:32])
	} else {
		blake3sum = "blake3.33B-" + cristalbase64.URLEncoding.EncodeToString(sum[:33])
	}
	return
}

func (cfg *Blake3SummerConfig) shouldExclude(path string) bool {
	base := filepath.Base(path)

	for _, xpre := range cfg.Xprefix.x {
		if strings.HasPrefix(base, xpre) {
			return true
		}
	}
	for _, xsuf := range cfg.Xsuffix.x {
		if strings.HasSuffix(base, xsuf) {
			return true
		}
	}
	if path != base {
		for _, xpre := range cfg.Xprefix.x {
			if strings.HasPrefix(path, xpre) {
				return true
			}
		}
		for _, xsuf := range cfg.Xsuffix.x {
			if strings.HasSuffix(path, xsuf) {
				return true
			}
		}
	}
	return false
}

func (cfg *Blake3SummerConfig) keep(path string) bool {

	if cfg.HasExcludes && cfg.shouldExclude(path) {
		return false
	}
	for _, glob := range cfg.Globs {
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
	di.FollowSymlinks = cfg.FollowSymLinks
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
		if cfg.HasExcludes && cfg.shouldExclude(path) {

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
			if cfg.HasExcludes && cfg.shouldExclude(path) {

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

func (cfg *Blake3SummerConfig) ScanFiles(files map[string]bool, results chan *PathSum) {
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

func (cfg *Blake3SummerConfig) ScanOneFile(path string, results chan *PathSum) (err error) {

	sum, err := cfg.Blake3OfFile(path)
	if err != nil {
		return nil
	}

	results <- &PathSum{Path: path, Sum: sum}
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

	if !cfg.FollowSymLinks {
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

	if cfg.MaxDepth > 0 && depth >= cfg.MaxDepth {
		vv("hit maxDepth at %v.  path = '%v'", depth, path)
		return filepath.SkipDir
	} else {
		//vv("depth(%v) <= maxDepth at %v.  path = '%v'", depth, cfg.MaxDepth, path)
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
		if !cfg.FollowSymLinks {
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
