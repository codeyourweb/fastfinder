# Compiling instruction for _FastFinder_ on Linux

_FastFinder_ was originally designed for Windows platform but it also work perfectly on Linux. Unlike  other Go programs, if you want to compile or run it from source, you will need to install some libraries and compilation tools. Indeed, _FastFinder_ is strongly dependent of libyara, go-yara and CGO. Here's a little step by step guide: 

## Before installation

Please ensure having:
* Go >= 1.17
* GOPATH / GOOS / GOARCH correctly set 
* administrator rights to install 

## Compile YARA

1/ download YARA latest release source tarball (https://github.com/VirusTotal/yara)
2/ Make sure you have `automake`, `libtool`, `make`, `gcc` and `pkg-config` installed in your system. 
2/ unzip and compile yara like this: 
```
tar -zxf yara-<version>.tar.gz
cd <version>.
./bootstrap.sh
./configure
make
make install
```
3/ Run the test cases to make sure that everything is fine:
```
make check
```

## Configure CGO
CGO will link libyara and compile C instructions used by _Fastfinder_ (through go-yara project). Compiler and linker flags have to be set via the CGO_CFLAGS and CGO_LDFLAGS environment variables like this:
```
export CGO_CFLAGS="-I<YARA_SRC_PATH>/libyara/include"
export CGO_LDFLAGS="-L<YARA_SRC_PATH>/libyara/.libs -lyara"
```

## You're ready to Go!
You can compile _FastFinder_ with the following command:
```
go build -tags yara_static -a -ldflags '-s -w' .
```
