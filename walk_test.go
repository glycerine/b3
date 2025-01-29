package main

import (
	"fmt"
	//"io"
	"iter"
	"os"
	"path/filepath"
	"testing"
)

// test the walk iterator

func PrintAll[V any](seq iter.Seq[V]) {
	for v := range seq {
		fmt.Println(v)
	}
}

func TestWalkDirsDFSIter(t *testing.T) {

	// So the linux source tree had 4597 leaf directories.
	//root := "github.com/torvalds/linux"

	// We don't have linux all checked out everywhere,
	// and it takes 3 seconds. Just scan locally.
	root := "."

	limit := 100000

	di := NewDirIter()

	k := 0
	next, stop := iter.Pull2(di.DirsDepthFirstLeafOnly(root))
	defer stop()

	for {
		dir, ok, valid := next()
		if !valid {
			vv("not valid, breaking, ok = %v", ok)
			break
		}
		if !ok {
			break
		}

		k++
		fmt.Println(dir)

		if k > limit {
			vv("break on limit")
			break
		}
	}
	vv("total leaf dir = %v", k)
}

func TestWalkDirs_FollowSymlinks(t *testing.T) {

	root := "test_root"

	os.RemoveAll(root) // cleanup any prior test output.
	defer os.RemoveAll(root)

	panicOn(os.MkdirAll(filepath.Join(root, "a/b/c/d"), 0700))
	panicOn(os.MkdirAll(filepath.Join(root, "z"), 0700))

	// two symlinks in a row
	panicOn(os.Symlink("../a", filepath.Join(root, "z/symlink2")))
	panicOn(os.Symlink("symlink2", filepath.Join(root, "z/symlink")))

	fd, err := os.Create(filepath.Join(root, "a/b/c/d/file0.txt"))
	panicOn(err)
	fd.Close()

	di := NewDirIter()
	di.FollowSymlinks = true
	next, stop := iter.Pull2(di.FilesOnly(filepath.Join(root, "z")))
	defer stop()

	seen := 0
	paths := make(map[string]bool)
	for {
		path, ok, valid := next()
		if !valid {
			//vv("not valid, breaking, ok = %v", ok)
			break
		}
		if !ok {
			break
		}
		//vv("path = '%v'", path)
		if fileExists(path) {
			seen++
			paths[path] = true
		}
	}
	if want, got := 2, seen; want != got {
		// there are 2 paths to file0.txt when resolving symlinks:
		// test_root/z/symlink/symlink2/a/b/c/d/file0.txt
		// test_root/z/symlink2/a/b/c/d/file0.txt
		//
		// both of which resolve ultimately to:
		//
		// test_root/a/b/c/d/file0.txt
		t.Fatalf("want %v, got %v seen files", want, got)
	}
	if len(paths) != 1 {
		t.Fatalf("expected only 1 unique path in paths")
	}
	if !paths["test_root/a/b/c/d/file0.txt"] {
		t.Fatalf("expected 'test_root/a/b/c/d/file0.txt' in paths")
	}
}
