![FastFinder Logo](./Icon.png)

# FastFinder

**A lightweight incident response tool for threat hunting and forensic triage**

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/github/license/codeyourweb/fastfinder?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/codeyourweb/fastfinder?style=flat-square)](https://github.com/codeyourweb/fastfinder/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/codeyourweb/fastfinder/go_build_windows.yml?style=flat-square&label=Windows)](https://github.com/codeyourweb/fastfinder/actions)
[![Build Status](https://img.shields.io/github/actions/workflow/status/codeyourweb/fastfinder/go_build_linux.yml?style=flat-square&label=Linux)](https://github.com/codeyourweb/fastfinder/actions)
[![Platform Support](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-brightgreen?style=flat-square)](#installation)

## ✨ Overview

FastFinder is a powerful, lightweight incident response tool designed for cybersecurity professionals conducting threat hunting, live forensics, and endpoint triage. Built for both Windows and Linux platforms, it excels at rapid suspicious file discovery using multiple detection criteria.

### 🔍 Key Detection Capabilities

- **Path-based Detection**: File path and name pattern matching
- **Hash Verification**: MD5, SHA1, and SHA256 checksum validation
- **Content Analysis**: Simple string matching and complex YARA rule evaluation
- **Multi-platform Support**: Native Windows and Linux compatibility

### 🛡️ Battle-Tested

- ✅ **Production Ready**: Successfully deployed in real-world incident response scenarios
- ✅ **Industry Validated**: Used by multiple CERTs, CSIRTs, and SOC teams
- ✅ **Comprehensive Examples**: Includes real malware samples and vulnerability scan scenarios

## 📸 Screenshots

![Basic UI](./screenshots/fastfinder_basicUI.jpg)
*Basic User Interface*

![Configuration](./screenshots/fastfinder_configuration_picker.jpg)
*Configuration Selection*

![Scan Results](./screenshots/fastfinder_matchs.jpg)
*Scan Results and Matches*

</details>

## 🚀 Installation

### Quick Start (Recommended)

**📥 [Download Latest Release](https://github.com/codeyourweb/fastfinder/releases/latest)**

### Building from Source

> ⚠️ **Note**: Compilation requires CGO and YARA dependencies. See platform-specific guides:

- 🪟 **Windows**: [Compilation Guide](README.windows-compilation.md)
- 🐧 **Linux**: [Compilation Guide](README.linux-compilation.md)

### Requirements

- **Runtime**: No dependencies required for pre-compiled binaries
- **Compilation**: Go 1.24+, CGO, libyara
- **Privileges**: Administrative rights recommended for full system access

## 📖 Usage

### Command Line Interface

```bash
fastfinder [OPTIONS]
```

### Available Options

| Option | Description | Default |
|--------|-------------|----------|
| `-h, --help` | Print help information | |
| `-c, --configuration` | Configuration file path | |
| `-b, --build` | Create standalone binary with embedded config | |
| `-o, --output` | Output log file path | |
| `-n, --no-window` | Hide application window | `false` |
| `-u, --no-userinterface` | Disable advanced UI | `false` |
| `-v, --verbosity` | Log verbosity level (1-4) | `3` |
| `-t, --triage` | Continuous monitoring mode | `false` |

### Verbosity Levels

- **Level 4**: Alerts only
- **Level 3**: Alerts and errors (default)
- **Level 2**: Alerts, errors, and I/O operations  
- **Level 1**: Full verbosity

### Quick Examples

```bash
# Basic scan with configuration file
./fastfinder -c config.yaml

# Continuous monitoring mode
./fastfinder -c config.yaml -t

# Silent mode with file output
./fastfinder -c config.yaml -n -o scan_results.log

# Create standalone executable
./fastfinder -b standalone_scanner.exe
```

> 💡 **Tip**: FastFinder can run with standard user privileges, but administrative rights provide access to all system files. 

### Scan and export file match according to your needs
configuration examples are available [there](./examples)
``` 
input:
    path: [] # match file path AND / OR file name based on simple string 
    content:
        grep: [] # match literal string value inside file content
        yara: [] # use yara rule and specify rules path(s) for more complex pattern search (wildcards / regex / conditions) 
        checksum: [] # parse for md5/sha1/sha256 in file content 
options:
    contentMatchDependsOnPathMatch: true # if true, paths are a pre-filter for content searchs. If false, paths and content both generate matchs
    findInHardDrives: true	# enumerate hard drive content
    findInRemovableDrives: true # enumerate removable drive content 
    findInNetworkDrives: true # enumerate network drive content
    findInCDRomDrives: true # enumerate physical CD-ROM and mounted iso / vhd...
output:
    copyMatchingFiles: true # create a copy of every matching file
    base64Files: true # base64 matched content before copy
    filesCopyPath: '' # empty value will copy matched files in the fastfinder.exe folder
advancedparameters:
    yaraRC4Key: ''    # yara rules can be (un)/ciphered using the specified RC4 key
    maxScanFilesize: 2048 #  ignore files up to maxScanFileSize Mb (default: 2048)               
    cleanMemoryIfFileGreaterThanSize: 512 # clean fastfinder internal memory after heavy file scan (default: 512Mb) 
``` 
### Search everywhere or in specified paths:
* use '?' in paths for simple char wildcard (eg. powershe??.exe)
* use '\\\*' in paths for multiple chars wildcard (eg. \\\*.exe)
* regular expressions are also available , just enclose paths with slashes (eg. /[0-9]{8}\\.exe/)
* environment variables can also be used (eg. %TEMP%\\myfile.exe)

### Important notes
* input path are always case INSENSITIVE
* content search on string (grep) are always case SENSITIVE
* backslashes SHOULD NOT be escaped (except with regular expressions)
For more informations, take a look at the [examples](./examples)

## 🤝 Contributing

We welcome contributions! Please see our contribution guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/codeyourweb/fastfinder.git
cd fastfinder

# Install dependencies (see compilation guides)
# Build from source
go build -tags yara_static -a -ldflags '-s -w' .

# Run tests
go test ./...
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🚀 Support

- **🐛 Report Issues**: [GitHub Issues](https://github.com/codeyourweb/fastfinder/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/codeyourweb/fastfinder/discussions)
- **📧 Security**: Report security vulnerabilities privately

## 📊 Project Stats

![GitHub stars](https://img.shields.io/github/stars/codeyourweb/fastfinder?style=social)
![GitHub forks](https://img.shields.io/github/forks/codeyourweb/fastfinder?style=social)


## 🙏 Acknowledgments

* **Hilko Bengen (@hillu)** for his wonderful [yara implementation in Go](https://github.com/hillu/go-yara) and also for his precious help debugging CGO issues 
* **Marc Ochsenmeier** for his precious help, feedbacks but also for having talking on my project
* **Vitali Kremez** ✝ for inspiring me on many aspects that made me build fastfinder
---

**Made with ❤️ by the cybersecurity community**  
Created by Jean-Pierre GARNIER (@codeyourweb) • 2021-2025
