package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

func Exit1IfVersionReq() {
	for _, a := range os.Args {
		if a == "-version" || a == "--version" {

			if bi, ok := debug.ReadBuildInfo(); ok {

				fmt.Fprintf(os.Stderr, "%v version: %+v\n", os.Args[0], bi)
				os.Exit(1)
			}
		}
	}
}
