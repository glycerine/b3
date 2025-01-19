package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/glycerine/rpc25519/hash"
)

type Blake3SummerConfig struct {
	Help bool

	paths []string
}

func (c *Blake3SummerConfig) SetFlags(fs *flag.FlagSet) {

	fs.BoolVar(&c.Help, "help", false, "show this help")
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

	var files []string

	for _, path := range cfg.paths {
		fi, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "b3 error on stat of target path '%v': '%v'", path, err)
			continue
		}
		if fi.IsDir() {
			// ignore
		} else {
			files = append(files, path)
		}
	}

	for _, path := range files {
		sum, err := hash.Blake3OfFile(path)
		panicOn(err)
		fmt.Printf("%v   %v\n", sum, path)
	}

}
