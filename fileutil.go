package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"syscall"
)

func fileExists(name string) bool {
	fi, err := os.Stat(name)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		return false
	}
	return true
}

func dirExists(name string) bool {
	fi, err := os.Stat(name)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		return true
	}
	return false
}

func fileSize(name string) (int64, error) {
	fi, err := os.Stat(name)
	if err != nil {
		return -1, err
	}
	return fi.Size(), nil
}

// IsWritable returns true if the file
// does not exist. Otherwise it checks
// the write bits. If any write bits
// (owner, group, others) are set, then
// we return true. Otherwise false.
func isWritable(path string) bool {
	if !fileExists(path) {
		return true
	}
	fileInfo, err := os.Stat(path)
	panicOn(err)

	// Get the file's mode (permission bits)
	mode := fileInfo.Mode()

	// Check write permission for owner, group, and others
	return mode&0222 != 0 // Write permission for any?
}

func copyFileDestSrc(topath, frompath string) (int64, error) {
	if !fileExists(frompath) {
		return 0, fs.ErrNotExist
	}

	src, err := os.Open(frompath)
	if err != nil {
		return 0, err
	}
	defer src.Close()

	dest, err := os.Create(topath)
	if err != nil {
		return 0, err
	}
	defer dest.Close()

	return io.Copy(dest, src)
}

// returns empty string on error.
func getFileOwnerName(filepath string) string {
	// Get file info
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return "" //, err
	}

	// Get system-specific file info
	stat := fileInfo.Sys()
	if stat == nil {
		return "" //, fmt.Errorf("no system-specific file info available")
	}

	// Get owner UID
	uid := stat.(*syscall.Stat_t).Uid

	// Look up user by UID
	owner, err := user.LookupId(fmt.Sprint(uid))
	if err != nil {
		return "" //, err
	}

	return owner.Username
}

func truncateFileToZero(path string) error {
	var perm os.FileMode
	f, err := os.OpenFile(path, os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("could not open file %q for truncation: %v", path, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("could not close file handler for %q after truncation: %v", path, err)
	}
	return nil
}
