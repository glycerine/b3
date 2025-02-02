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
prefixes and suffixes, respectively. These can be used to turn off the
default ignored names:

~~~
$ b3 -x '' -xs ''  # scan all files, no default ignores.
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
  
  -mt
    	include modtime in the hash (helpful for verifying it has been restored)
  
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

simple benchmarks
----------
`b3` is this Go repo. It uses https://github.com/glycerine/blake3 for multi-core file reading and hashing.

`b3sum` is the Rust Blake3, multi-threaded command line utility. https://crates.io/crates/b3sum and  https://github.com/BLAKE3-team/BLAKE3

`sha3sum` is a C implimentation of the SHA3 variants. https://git.maandree.se/sha3sum/about/

~~~

On this Ubuntu image (6.7GB):

  6.7G Jan 12 02:13 Ubuntu_24.04_VB_LinuxVMImages.COM.vdi

## sha-256 and sha-512 cannot be parallelized.
$ time sha3sum -a 256 Ubuntu_24.04_VB_LinuxVMImages.COM.vdi 
8e291fcde88b7aab44c902cb7edf32fc897303b8bcc29197aefd721db929db23  Ubuntu_24.04_VB_LinuxVMImages.COM.vdi

real	0m25.436s
user	0m23.238s
sys	0m2.114s

$ time sha3sum -a 256 Ubuntu_24.04_VB_LinuxVMImages.COM.vdi 
8e291fcde88b7aab44c902cb7edf32fc897303b8bcc29197aefd721db929db23  Ubuntu_24.04_VB_LinuxVMImages.COM.vdi

real	0m25.597s
user	0m23.312s
sys	0m2.134s

$ time b3sum   Ubuntu_24.04_VB_LinuxVMImages.COM.vdi # b3sum in Rust, many threads.
41b19084303db930f86e233d9b5f67c1100803230f8f80286946f94a62426c31  Ubuntu_24.04_VB_LinuxVMImages.COM.vdi

real	0m0.929s
user	0m4.911s
sys	0m1.835s

$ time b3 -hex -f Ubuntu_24.04_VB_LinuxVMImages.COM.vdi # b3 in Go, many threads.
41b19084303db930f86e233d9b5f67c1100803230f8f80286946f94a62426c31   Ubuntu_24.04_VB_LinuxVMImages.COM.vdi

real	0m0.611s
user	0m3.258s
sys	0m1.146s


$ time sha3sum -a 512 Ubuntu_24.04_VB_LinuxVMImages.COM.vdi 
f165f4ff3159ecc436a5cae0e1523952f2a8994f2159a3ab749eb5d1be0bdfe838afe89c7a9bff142cbe18413504671cac4aa1139fbca28c13b3490d960028c8  Ubuntu_24.04_VB_LinuxVMImages.COM.vdi

real	0m45.270s
user	0m42.185s
sys	0m2.612s

$ time sha3sum -a 512 Ubuntu_24.04_VB_LinuxVMImages.COM.vdi 
f165f4ff3159ecc436a5cae0e1523952f2a8994f2159a3ab749eb5d1be0bdfe838afe89c7a9bff142cbe18413504671cac4aa1139fbca28c13b3490d960028c8  Ubuntu_24.04_VB_LinuxVMImages.COM.vdi

real	0m44.996s
user	0m42.058s
sys	0m2.553s

# conclusion: blake3 can be 40x faster than sha256.
#                       and 70x faster than sha512.
~~~


-----
Author: Jason E. Aten, Ph.D.

License: 3-clause BSD style license, the same as Go. See the LICENSE file.

