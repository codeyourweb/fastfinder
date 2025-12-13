# Linux Compilation Guide

![Linux](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)
![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go)
![GCC](https://img.shields.io/badge/Compiler-GCC-red?style=for-the-badge&logo=gnu)

## 📝 Overview

This guide provides step-by-step instructions for compiling FastFinder from source on Linux systems. While FastFinder was originally designed for Windows, it works perfectly on Linux with proper dependency setup.

## ⚙️ Prerequisites

### System Requirements

- **Go 1.24+** installed and configured
- **GCC compiler** and build tools
- **Root/sudo privileges** for system package installation
- **4GB+ RAM** recommended for compilation

### Environment Variables

Ensure these are properly configured:

```bash
# Verify Go installation
go version
echo $GOPATH
echo $GOOS     # should be "linux"
echo $GOARCH   # typically "amd64"
```

## 🛠️ Step 1: Install System Dependencies

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    automake \
    libtool \
    make \
    gcc \
    pkg-config \
    git \
    libssl-dev
```

### CentOS/RHEL/Rocky Linux

```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y \
    automake \
    libtool \
    make \
    gcc \
    pkgconfig \
    git \
    openssl-devel
```

### Fedora

```bash
sudo dnf groupinstall -y "C Development Tools and Libraries"
sudo dnf install -y \
    automake \
    libtool \
    make \
    gcc \
    pkgconf \
    git \
    openssl-devel
```

> ⚠️ **Fedora-specific workaround**: After installing YARA, you may encounter library linking issues. See the [troubleshooting section](#fedora-library-workaround) below for the required additional steps.

### Arch Linux

```bash
sudo pacman -S \
    base-devel \
    automake \
    libtool \
    make \
    gcc \
    pkgconfig \
    git \
    openssl
```

## 🔧 Step 2: Build YARA Library

### 2.1 Download YARA Source

```bash
# Create build directory
mkdir -p ~/build && cd ~/build

# Download latest stable release
YARA_VERSION="4.5.0"  # Check https://github.com/VirusTotal/yara/releases for latest
wget https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz
tar -xzf v${YARA_VERSION}.tar.gz
cd yara-${YARA_VERSION}
```

### 2.2 Configure and Build YARA

```bash
# Generate build scripts
./bootstrap.sh

# Configure with optimization
./configure --enable-cuckoo --enable-magic --enable-dotnet

# Build with parallel jobs
make -j$(nproc)

# Run tests to verify build
make check

# Install system-wide
sudo make install

# Update library cache
sudo ldconfig
```

### 2.3 Verify YARA Installation

```bash
# Test YARA binary
yara --version

# Verify library linking
pkg-config --cflags --libs yara

# Test with simple rule
echo 'rule test { condition: true }' | yara /dev/stdin /bin/ls
```

## 🌐 Step 3: Configure CGO Environment

### 3.1 Set Build Flags

CGO requires specific flags to link with the YARA library:

```bash
# Add to your ~/.bashrc or ~/.profile
export CGO_CFLAGS="-I/usr/local/include"
export CGO_LDFLAGS="-L/usr/local/lib -lyara"
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"

# Reload environment
source ~/.bashrc
```

### 3.2 Alternative: Custom Installation Path

If you installed YARA to a custom prefix:

```bash
# Example for /opt/yara installation
export CGO_CFLAGS="-I/opt/yara/include"
export CGO_LDFLAGS="-L/opt/yara/lib -lyara"
export PKG_CONFIG_PATH="/opt/yara/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/opt/yara/lib:$LD_LIBRARY_PATH"
```

## 🚀 Step 4: Build FastFinder

### 4.1 Download Source Code

```bash
# Option 1: Clone repository
git clone https://github.com/codeyourweb/fastfinder.git
cd fastfinder

# Option 2: Using go modules
go mod download github.com/codeyourweb/fastfinder
```

### 4.2 Build FastFinder

```bash
# Verify CGO is enabled
go env CGO_ENABLED  # should return "1"

# Build with static YARA linking
go build -tags yara_static -a -ldflags '-s -w' .

# Alternative: Build with dynamic linking
go build -ldflags '-s -w' .
```

### 4.3 Create Optimized Release Build

```bash
# Static build for distribution
CGO_ENABLED=1 go build \
    -tags yara_static \
    -a \
    -ldflags '-s -w -extldflags "-static"' \
    -o fastfinder-linux-amd64 .

# Verify static linking
ldd fastfinder-linux-amd64  # should show "not a dynamic executable"
```

## ✨ Post-Installation

### Verify Installation

```bash
# Test the binary
./fastfinder --help

# Check version and build info
./fastfinder --version

# Run with a simple configuration
./fastfinder -c examples/example_configuration_linux.yaml
```

### Install System-Wide (Optional)

```bash
# Copy to system binary directory
sudo cp fastfinder /usr/local/bin/

# Make available system-wide
sudo chmod +x /usr/local/bin/fastfinder

# Verify system installation
fastfinder --version
```

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `yara.h: No such file or directory` | Install YARA development headers or check CGO_CFLAGS |
| `undefined reference to 'yr_*'` | Verify YARA library installation and CGO_LDFLAGS |
| `pkg-config: command not found` | Install pkg-config package |
| `cgo: C compiler "gcc" not found` | Install build-essential or equivalent |
| `permission denied` | Check file permissions or use sudo for installation |

### Debug Commands

```bash
# Check YARA installation
yara --version
pkg-config --exists yara && echo "YARA found" || echo "YARA missing"

# Verify CGO environment
echo "CGO_CFLAGS: $CGO_CFLAGS"
echo "CGO_LDFLAGS: $CGO_LDFLAGS"
go env CGO_ENABLED

# Test CGO compilation
go env -w CGO_ENABLED=1
go test -v github.com/hillu/go-yara/v4
```

### Fedora Library Workaround

**Problem**: On Fedora systems, you may encounter the error:
```
fastfinder: error while loading shared libraries: libyara.so.10: cannot open shared object file: No such file or directory
```

**Root Cause**: Fedora installs YARA libraries in `/usr/local/lib` but this path may not be in the system's library search path.

**Solution**:

1. **Verify YARA library location**:
   ```bash
   ls -la /usr/local/lib/libyara*
   # Should show: libyara.a, libyara.la, libyara.so, libyara.so.10, etc.
   ```

2. **Create library configuration file**:
   ```bash
   sudo tee /etc/ld.so.conf.d/yara-x86_64.conf << EOF
   /usr/local/lib
   EOF
   ```

3. **Update library cache**:
   ```bash
   sudo ldconfig
   ```

4. **Verify library is found**:
   ```bash
   ldconfig -p | grep libyara
   # Should show: libyara.so.10 (libc6,x86-64) => /usr/local/lib/libyara.so.10
   ```

5. **Update CGO flags for Fedora**:
   ```bash
   export CGO_CFLAGS="-I/usr/local/include"
   export CGO_LDFLAGS="-L/usr/local/lib -lyara"
   export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"
   export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
   ```

> 📖 **Reference**: This workaround addresses the issue documented in [GitHub Issue #5](https://github.com/codeyourweb/fastfinder/issues/5)

### Build Variants

```bash
# Debug build with symbols
go build -tags yara_static -gcflags="-N -l" .

# Cross-compilation for other architectures
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc \
    go build -tags yara_static .

# Build with race detector (development only)
go build -race .
```

## 📚 Additional Resources

- **YARA Documentation**: [https://yara.readthedocs.io/](https://yara.readthedocs.io/)
- **Go-YARA Bindings**: [https://github.com/hillu/go-yara](https://github.com/hillu/go-yara)
- **CGO Documentation**: [https://golang.org/cmd/cgo/](https://golang.org/cmd/cgo/)

---

🚀 **Success!** You should now have a working `fastfinder` binary.

🔗 **Next Steps**: See the main [README](README.md) for usage instructions and configuration examples.
