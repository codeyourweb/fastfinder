# FastFinder Docker Helper Script (PowerShell)
# Simplifies common Docker operations for FastFinder on Windows

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

# Colors for output
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Show usage
function Show-Usage {
    @"
FastFinder Docker Helper (PowerShell)

Usage: .\docker-helper.ps1 [command] [options]

Commands:
  build-binaries     Build Linux and Windows binaries with YARA
  build-linux        Build Linux binary with YARA support
    build-windows      Build Windows binary with YARA support
    build-runtime      Build the runtime image (FastFinder inside container)
    run-runtime        Run FastFinder inside a container named "runtime"
                         (add -Interactive to drop into shell instead of running the scan)
  clean              Remove Docker build cache
  help               Show this help message

Examples:
  # Build both Linux and Windows binaries
  .\docker-helper.ps1 build-binaries

  # Build only Linux binary
  .\docker-helper.ps1 build-linux

    # Build only Windows binary
    .\docker-helper.ps1 build-windows

    # Build runtime image
    .\docker-helper.ps1 build-runtime

    # Run FastFinder inside a privileged container named "runtime"
        .\docker-helper.ps1 run-runtime -ConfigPath ./examples/ -ScanPath /your/root/path

    # Start runtime container in interactive shell (no scan)
    .\docker-helper.ps1 run-runtime -Interactive

  # Clean up Docker build cache
  .\docker-helper.ps1 clean

For more details, see docker\README.md
"@
}

# Build both binaries
function Build-Binaries {
    Write-Info "Building FastFinder binaries for Linux and Windows..."
    
    Push-Location $ProjectRoot
    
    if (-not (Test-Path "bin")) {
        New-Item -ItemType Directory -Path "bin" | Out-Null
    }
    
    # Build Linux binary
    Write-Info "Building Linux binary with YARA support..."
    docker build `
        --target binaries `
        --output type=local,dest=./bin `
        -f docker/Dockerfile.builder `
        .
    
    # Build Windows binary
    Write-Info "Building Windows binary with YARA support..."
    docker build `
        --target binaries `
        --output type=local,dest=./bin `
        -f docker/Dockerfile.windows-builder `
        .
    
    if ((Test-Path "bin/fastfinder-linux-amd64") -and (Test-Path "bin/fastfinder-windows-amd64.exe")) {
        Write-Success "Both binaries built successfully!"
        Write-Info "Linux binary: bin/fastfinder-linux-amd64"
        Write-Info "Windows binary: bin/fastfinder-windows-amd64.exe"
        
        Get-ChildItem bin/fastfinder-* | Format-Table Name, Length, LastWriteTime
    } else {
        Write-Error "Binary build failed!"
        Pop-Location
        exit 1
    }
    
    Pop-Location
}

# Build Linux binary only
function Build-Linux {
    Write-Info "Building Linux binary with YARA support..."
    
    Push-Location $ProjectRoot
    
    if (-not (Test-Path "bin")) {
        New-Item -ItemType Directory -Path "bin" | Out-Null
    }
    
    docker build `
        --target binaries `
        --output type=local,dest=./bin `
        -f docker/Dockerfile.builder `
        .
    
    if (Test-Path "bin/fastfinder-linux-amd64") {
        Write-Success "Linux binary built successfully!"
        Get-ChildItem bin/fastfinder-linux-amd64 | Format-Table Name, Length, LastWriteTime
    } else {
        Write-Error "Build failed!"
        Pop-Location
        exit 1
    }
    
    Pop-Location
}

# Build Windows binary only
function Build-Windows {
    Write-Info "Building Windows binary with YARA support..."
    
    Push-Location $ProjectRoot
    
    if (-not (Test-Path "bin")) {
        New-Item -ItemType Directory -Path "bin" | Out-Null
    }
    
    docker build `
        --target binaries `
        --output type=local,dest=./bin `
        -f docker/Dockerfile.windows-builder `
        .
    
    if (Test-Path "bin/fastfinder-windows-amd64.exe") {
        Write-Success "Windows binary built successfully!"
        Get-ChildItem bin/fastfinder-windows-amd64.exe | Format-Table Name, Length, LastWriteTime
    } else {
        Write-Error "Build failed!"
        Pop-Location
        exit 1
    }
    
    Pop-Location
}

# Build runtime image that can execute FastFinder inside a container
function Build-Runtime {
    Write-Info "Building FastFinder runtime image..."

    Push-Location $ProjectRoot

    docker build `
        -f docker/Dockerfile.runtime `
        -t fastfinder:runtime `
        .

    Write-Success "Runtime image built as fastfinder:runtime"

    Pop-Location
}

# Run FastFinder in a privileged container named "runtime"
function Run-Runtime {
    param(
        [string]$ConfigPath = "$ProjectRoot/examples",
        [string]$ScanPath = "$ProjectRoot",
        [switch]$Interactive
    )

    # Ensure runtime image exists; build if missing
    $imageExists = $false
    try {
        docker image inspect fastfinder:runtime 1>$null 2>$null
        $imageExists = $true
    } catch {
        $imageExists = $false
    }

    if (-not $imageExists) {
        Build-Runtime
    }

    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Config path not found: $ConfigPath"
        return
    }

    $ResolvedConfig = Resolve-Path $ConfigPath
    $configIsDir = (Get-Item $ResolvedConfig).PSIsContainer
    $configFileInContainer = "/config/config.yml"

    if ($configIsDir) {
        # Mount directory; expect config.yml inside
        $HostConfigDir = $ResolvedConfig
    } else {
        # Mount parent dir; keep config filename
        $HostConfigDir = Split-Path $ResolvedConfig
        $configFileInContainer = "/config/" + (Split-Path $ResolvedConfig -Leaf)
    }

    # Allow Linux-style scan paths (e.g. /host) without Windows Test-Path check
    $ScanPathToUse = $ScanPath
    $isLinuxStyle = $ScanPath -match '^/'
    if (-not $isLinuxStyle) {
        if (-not (Test-Path $ScanPath)) {
            Write-Error "Scan path not found: $ScanPath"
            return
        }
        $ScanPathToUse = Resolve-Path $ScanPath
    }

    Write-Info "Running FastFinder in container 'runtime' (privileged for drive discovery)..."

    try {
        docker rm -f runtime 1>$null 2>$null
    } catch {}

    $entrypointArgs = @()
    $commandArgs = @()
    if ($Interactive) {
        $entrypointArgs = @("--entrypoint", "/bin/bash")
        $commandArgs = @()
    } else {
        $commandArgs = @("-c", $configFileInContainer)
    }

    docker run `
        --rm `
        -it `
        --name runtime `
        --privileged `
        --pid=host `
        --cap-add SYS_ADMIN `
        --cap-add SYS_RAWIO `
        -e "FASTFINDER_DISABLE_MUTEX=1" `
        -v "${HostConfigDir}:/config" `
        -v "${ScanPathToUse}:/scan:ro" `
        @entrypointArgs `
        fastfinder:runtime `
        @commandArgs
}

# Clean up Docker build cache
function Clean-Docker {
    Write-Warning "Cleaning up Docker build cache..."
    
    # Prune build cache
    Write-Info "Pruning Docker build cache..."
    docker builder prune -f
    
    Write-Success "Cleanup complete!"
}

# Main logic
$Command = if ($args.Count -gt 0) { $args[0] } else { "help" }

switch ($Command) {
    "build-binaries" {
        Build-Binaries
    }
    "build-linux" {
        Build-Linux
    }
    "build-windows" {
        Build-Windows
    }
    "build-runtime" {
        Build-Runtime
    }
    "run-runtime" {
        if ($args.Length -gt 1) {
            $runtimeArgs = $args[1..($args.Length-1)]
            Run-Runtime @runtimeArgs
        } else {
            Run-Runtime
        }
    }
    "clean" {
        Clean-Docker
    }
    default {
        if ($Command -ne "help") {
            Write-Error "Unknown command: $Command"
            Write-Host ""
        }
        Show-Usage
    }
}
