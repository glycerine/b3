b3
==

`b3` is a simple utility to compute the blake3 cryptographic
hash of files. 

The reported string is the first 33 bytes (264 bits) of 
the 512-bit blake3 hash. It is URL-safe encoded in base64, 
and prefixed with the distinguishing "blake3.33B-" format label.

The file subset selection syntax is a simple strings.Contains()
based matching. Each filter string will be tested against
the whole path. If strings.Contains(path, filter), then that
path will be checksummed. For more complex
filtering, create your path list before hand and 
use the `b3 -i` flag to feed the paths (one per line)
to `b3` on stdin.

Example:

~~~
$ b3
blake3.33B-HJUzsI89QG6-xECkcpRxGNel-Ui-uIi9g8eeGL1XSaQz   README.md
blake3.33B-iZEGnHFmCCkM0_PdsHNCyCgVR7za3uBfeBIlEYXxwwQf   b3.go
blake3.33B-0qtEYlOq4UxMfbn9DGyd9FWaeIitA94pMhArHjd3oK41   fileutil.go
blake3.33B-w5UsA6LD_FqoOxUcl3wbmwh9V1FhhBdAEvPn5T9yqc47   go.mod
blake3.33B-X2h_3xgz4lB-QmnknLG-xuv2WU7w6hPbHJOmqrX6TDM1   go.sum
blake3.33B-z-GPDZa-Cayr-oFi3VUfec4Y1zGtUGqhp2VM-gO2Sp42   vprint.go
$
~~~

* Notes:

With no arguments, we assume scan the current directory.

Paths are returned in sorted order.

Install with: `go install github.com/glycerine/b3@latest`

By default, file/dir names with the '~' suffix are ignored.
This is a convenience for emacs users. The same applies to
the full path.

By default, file/dir names starting with "_" are ignored. This is the same
convention that the go tools use. The same applies to full paths.

The `b3 -x` and `b3 -xs` can be used (multiple times) to change the ignored
prefixes and suffixes, respectively. These can be use to turn off the
default ignored names:

~~~
$ b3 -x '' -xs '' *  # scan all files, no default ignores.
~~~

To scan recursively, use the `b3 -r` flag. This will use
all available cores to checksum directories in parallel.
The scan will follow symlinks. Use `-nosym` to prevent this.


Use `b3 -version` to get version information.

See `b3 -h` for all flags.
~~~
$ b3 -h
Usage of b3:
  -help
    	show this help
        
  -i	read list of paths on stdin
  
  -nosym
    	do not follow symlinked directories

  -r	recursive checksum sub-directories
  
  -version
    	show version of b3/dependencies
  -x value
    	file name prefix to exclude (multiple -x okay; default: '_')
  -xs value
    	file name suffix to exclude (multiple -xs okay; default: '~')
~~~

-----
Author: Jason E. Aten, Ph.D.

License: 3-clause BSD style license, the same as Go. See the LICENSE file.

