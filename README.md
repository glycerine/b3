b3
==

`b3` is a simple utility to compute the blake3 cryptographic
hash of files. 

The reported string is the first 32 bytes (256 bits) of 
the 512-bit blake3 hash. It is URL-safe encoded in base64, 
and prefixed with the distinguishing "blake3.32B-" format label.

The file subset selection syntax is a simple strings.Contains()
based matching. Each filter string will be tested against
the path. If strings.Contains(path, filter), then that
path will be scanned. For more complex
filtering, use the `b3 -i` flag to feed the paths (one per line)
to `b3` on stdin.

Example:

~~~
$ b3
blake3.32B-HJUzsI89QG6-xECkcpRxGNel-Ui-uIi9g8eeGL1XSaQ=   README.md
blake3.32B-iZEGnHFmCCkM0_PdsHNCyCgVR7za3uBfeBIlEYXxwwQ=   b3.go
blake3.32B-0qtEYlOq4UxMfbn9DGyd9FWaeIitA94pMhArHjd3oK4=   fileutil.go
blake3.32B-w5UsA6LD_FqoOxUcl3wbmwh9V1FhhBdAEvPn5T9yqc4=   go.mod
blake3.32B-X2h_3xgz4lB-QmnknLG-xuv2WU7w6hPbHJOmqrX6TDM=   go.sum
blake3.32B-z-GPDZa-Cayr-oFi3VUfec4Y1zGtUGqhp2VM-gO2Sp4=   vprint.go
$
~~~

* Notes:

With no arguments, we assume that `b3 *` was requested.

Paths are returned in sorted order.

Install with: `go install github.com/glycerine/b3@latest`

By default, file/dir names with the '~' suffix are ignored.
This is a convenience for emacs users.

By default, file/dir names starting with "_" are ignored. This is the same
convention that the go tools use.

The `b3 -x` and `b3 -xs` can be used (multiple times) to change the excluded
prefixes and suffixes, respectively. These can be use to turn off the
default exclusions:

~~~
$ b3 -x '' -xs '' *  # scan all files, no default exclusions.
~~~

To scan recursively, use the `b3 -r` flag. This will use
all available cores to checksum directories in parallel.
The scan will follow symlinks. Use `-nosym` to prevent this.

See `b3 -h` for all flags.

Use `b3 -version` to get version information.


-----
Author: Jason E. Aten, Ph.D.

License: 3-clause BSD style license, the same as Go. See the LICENSE file.

