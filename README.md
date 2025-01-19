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

~~~



