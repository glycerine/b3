b3
==

A simple utility to compute the blake3 cryptographic
hash of files. The reported string is the first 32
bytes (256 bits) of the 512-bit blake3 hash,
URL-safe encoded in base64, and prefixed with
the distinguishing "blake3.32B-" format label.

The glob syntax supported is the same as filepath.Match().
See https://pkg.go.dev/path/filepath#Match


Example:

~~~
$ b3 *
blake3.32B-HJUzsI89QG6-xECkcpRxGNel-Ui-uIi9g8eeGL1XSaQ=   README.md
blake3.32B-iZEGnHFmCCkM0_PdsHNCyCgVR7za3uBfeBIlEYXxwwQ=   b3.go
blake3.32B-0qtEYlOq4UxMfbn9DGyd9FWaeIitA94pMhArHjd3oK4=   fileutil.go
blake3.32B-w5UsA6LD_FqoOxUcl3wbmwh9V1FhhBdAEvPn5T9yqc4=   go.mod
blake3.32B-X2h_3xgz4lB-QmnknLG-xuv2WU7w6hPbHJOmqrX6TDM=   go.sum
blake3.32B-z-GPDZa-Cayr-oFi3VUfec4Y1zGtUGqhp2VM-gO2Sp4=   vprint.go
$
~~~

By default, emacs ~ files are ignored. Use `b3 -all` to include them.

-----
Author: Jason E. Aten, Ph.D.

License: 3-clause BSD style license, the same as Go. See the LICENSE file.

