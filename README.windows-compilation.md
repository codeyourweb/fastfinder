
# Installing _FastFinder_ on Windows

_FastFinder_ is design for Windows platform but it's a little bit tricky because it's strongly dependant of go-yara and CGO. Here's a little step by step guide: 

## Before installation

All the installation process will be done with msys2/mingw terminal. In order to avoid any error, you have to ensure that your installation directories don't contains space or special characters. I haven't tested to install as a simple user, I strongly advise you to install everything with admin privileges on top of your c:\ drive.

For the configurations and examples below, my install paths are:

* GO: c:\Go
* GOPATH: C:\Users\myuser\go
* Msys2: c:\msys64
* Git: c:\Git 

## Install msys2 and dependencies:

First of all, note that you won't be able to get _FastFinder_ working if the dependencies are compiled with another compiler than GCC. There is currently some problems with CGO when external libraries are compiled with Visual C++, so no need to install Visual Studio or vcpkg.

* Download msys2 [from the official website](https://www.msys2.org/) and install it
* there, you will find two distincts binaries shorcut "MSYS2 MSYS" and "MSYS2 MinGW 64bits". Please launch this second one.
* install dependencies with the following command line: `pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-pkg-config base-devel openssl-devel`
* add environment variables in mingw terminal: `export PATH=$PATH:/c/Go/bin:/c/msys64/mingw64/bin:/c/Git/bin`

## Download and compile libyara

It's strongly advised NOT to clone VirusTotal's YARA repository but to download the source code of the latest release. If you compile libyara from the latest commit, it could generate some side effects when linking this library with _FastFinder_ and GCO.

* download latest VirusTotal release source code [from here](https://github.com/VirusTotal/yara/releases)
* unzip the folder in a directory without space and special char
* in mingw terminal, go to yara directory (backslash have to be replace with slash eg. cd c:/yara)
* compile and install using the following command: `./bootstrap.sh &&./configure && make && make install`  

## Configure your OS

With this step, you won't need to use mingw terminal anymore and you will be able to use Go to install _FastFinder_ and compile your projects directly from Windows cmd / powershell.

Make sure you have the following as system environment variables (not user env vars). If not, create them:
```
GOARCH=<your-architecture> (eg. amd64)
GOOS=windows
CGO_CFLAGS=-IC:/msys64/mingw64/include
CGO_LDFLAGS=-LC:/msys64/mingw64/lib -lyara -lcrypto
PKG_CONFIG_PATH=C:/msys64/mingw64/lib/pkgconfig
```
You also need C:\msys64\mingw64\bin in your system PATH env vars.

Make sure you have got the following user environment var (not system var):

    GOPATH=%USERPROFILE%\go

Note that paths must be written with slashs and not backslash. As already said, don't use path with spaces or special characters.

## Download, Install and compile FastFinder
Now, from Windows cmd or Powershell, you can install _FastFinder_: `go get github.com/codeyourweb/fastfinder`
Compilation should be done with: `go build -tags yara_static -a -ldflags '-extldflags "-static"' .` 
