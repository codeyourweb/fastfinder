# Windows Compilation Guide

![Windows](https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows)
![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go)
![GCC](https://img.shields.io/badge/Compiler-GCC-red?style=for-the-badge&logo=gnu)

## 📝 Overview

This guide walks you through compiling FastFinder from source on Windows. The process requires setting up a complete CGO environment with YARA dependencies.

> ⚠️ **Important**: FastFinder depends on [go-yara](https://github.com/hillu/go-yara) and CGO, which requires specific compiler configurations.

## ⚙️ Prerequisites

### System Requirements

- **Windows 10/11** (64-bit recommended)
- **Administrator privileges** for installation
- **8GB+ RAM** for compilation process
- **2GB+ free disk space**

### Installation Paths

> 🚨 **Critical**: Avoid paths with spaces or special characters

| Component | Recommended Path |
|-----------|------------------|
| Go | `C:\Go` |
| GOPATH | `C:\Users\<username>\go` |
| MSYS2 | `C:\msys64` |
| Git | `C:\Git` | 

## 🛠️ Step 1: Install MSYS2 and Dependencies

### 1.1 Download and Install MSYS2

1. **Download MSYS2** from the [official website](https://www.msys2.org/)
2. **Install to** `C:\msys64` (avoid paths with spaces)
3. **Launch** `MSYS2 MinGW 64-bit` terminal (not the regular MSYS2 terminal)

### 1.2 Install Build Tools

> ⚠️ **Note**: We use GCC instead of Visual Studio due to CGO compatibility requirements

```bash
# Update package database
pacman -Sy

# Install essential build tools
pacman -S mingw-w64-x86_64-toolchain \
          pkg-config \
          mingw-w64-x86_64-pkg-config \
          base-devel \
          openssl-devel \
          autoconf \
          automake \
          libtool \
          mingw-w64-x86_64-protobuf-c
```

### 1.3 Configure Environment

Add these paths to your MinGW environment:

```bash
export PATH=$PATH:/c/Go/bin:/c/msys64/mingw64/bin:/c/Git/bin
```

## 🔧 Step 2: Build YARA Library

### 2.1 Download YARA Source

> ⚠️ **Important**: Use official releases, not the latest commit from the repository

1. **Download** the latest stable release from [YARA Releases](https://github.com/VirusTotal/yara/releases)
2. **Extract** to a path without spaces (e.g., `C:\yara-4.x.x`)

### 2.2 Compile YARA

In the **MSYS2 MinGW 64-bit** terminal:

```bash
# Navigate to YARA directory (use forward slashes)
cd /c/yara-4.x.x

# Generate build scripts
./bootstrap.sh

# Configure build (install to MinGW prefix)
./configure --prefix=/mingw64

# Compile (this may take several minutes)
make

# Install libraries
make install
```

### 2.3 Verify Installation

```bash
# Check if YARA is properly installed
pkg-config --cflags --libs yara

# Test YARA binary
yara --version
```
## 🌐 Step 3: Configure System Environment

### 3.1 System Environment Variables

Add these to your **System Environment Variables** (not user variables):

```cmd
GOARCH=amd64
GOOS=windows
CGO_CFLAGS=-IC:/msys64/mingw64/include
CGO_LDFLAGS=-LC:/msys64/mingw64/lib -lyara -lcrypto
PKG_CONFIG_PATH=C:/msys64/mingw64/lib/pkgconfig
```

### 3.2 Update System PATH

Add to your **System PATH** environment variable:

```
C:\msys64\mingw64\bin
C:\Go\bin
```

### 3.3 User Environment Variables

Set this **User Environment Variable**:

```cmd
GOPATH=%USERPROFILE%\go
```

> 📝 **Note**: Use forward slashes in CGO flags, backslashes in PATH variables

## 🚀 Step 4: Build FastFinder

### 4.1 Download Source Code

```bash
# Option 1: Using go get (from any command prompt)
go get github.com/codeyourweb/fastfinder
cd %GOPATH%\src\github.com\codeyourweb\fastfinder

# Option 2: Clone directly
git clone https://github.com/codeyourweb/fastfinder.git
cd fastfinder
```

### 4.2 Compile FastFinder

```bash
# Build with static linking
go build -tags yara_static -a -ldflags '-extldflags "-static"' .

# Build optimized release version
go build -tags yara_static -a -ldflags '-s -w -extldflags "-static"' .
```

### 4.3 Verify Build

```bash
# Test the executable
.\fastfinder.exe --help

# Check dependencies (should show minimal external deps)
dumpbin /dependents fastfinder.exe
```

## ✨ Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `cgo: C compiler "gcc" not found` | Ensure MinGW64 is in PATH |
| `pkg-config not found` | Install `mingw-w64-x86_64-pkg-config` |
| `yara.h: No such file` | Verify CGO_CFLAGS points to correct include path |
| `undefined reference to 'yr_*'` | Check CGO_LDFLAGS and YARA installation |
| `access denied` during build | Run as administrator or check antivirus settings |

### Verification Commands

```bash
# Verify environment
echo $CGO_CFLAGS
echo $CGO_LDFLAGS
echo $PKG_CONFIG_PATH

# Test CGO compilation
go env CGO_ENABLED  # should return "1"

# Test YARA linking
pkg-config --exists yara && echo "YARA found" || echo "YARA missing"
```

---

🚀 **Success!** You should now have a working `fastfinder.exe` binary.

🔗 **Next Steps**: See the main [README](README.md) for usage instructions and examples. 
