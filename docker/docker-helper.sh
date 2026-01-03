#!/bin/bash

# FastFinder Docker Helper Script
# Simplifies common Docker operations for FastFinder

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Show usage
show_usage() {
    cat << EOF
FastFinder Docker Helper

Usage: $0 [command] [options]

Commands:
  build-binaries     Build Linux and Windows binaries with YARA
  build-linux        Build Linux binary with YARA support
  build-windows      Build Windows binary with YARA support
  clean              Remove Docker build cache
  help               Show this help message

Examples:
  # Build both Linux and Windows binaries
  $0 build-binaries

  # Build only Linux binary
  $0 build-linux

  # Build only Windows binary
  $0 build-windows

  # Clean up Docker build cache
  $0 clean

For more details, see docker/README.md
EOF
}

# Build both binaries
build_binaries() {
    print_info "Building FastFinder binaries for Linux and Windows..."
    
    cd "$PROJECT_ROOT"
    mkdir -p bin
    
    # Build Linux binary
    print_info "Building Linux binary with YARA support..."
    docker build \
        --target binaries \
        --output type=local,dest=./bin \
        -f docker/Dockerfile.builder \
        .
    
    # Build Windows binary
    print_info "Building Windows binary with YARA support..."
    docker build \
        --target binaries \
        --output type=local,dest=./bin \
        -f docker/Dockerfile.windows-builder \
        .
    
    if [ -f "bin/fastfinder-linux-amd64" ] && [ -f "bin/fastfinder-windows-amd64.exe" ]; then
        print_success "Both binaries built successfully!"
        print_info "Linux binary: bin/fastfinder-linux-amd64"
        print_info "Windows binary: bin/fastfinder-windows-amd64.exe"
        
        # Make Linux binary executable
        chmod +x bin/fastfinder-linux-amd64
        
        # Show file sizes
        ls -lh bin/fastfinder-*
    else
        print_error "Binary build failed!"
        exit 1
    fi
}

# Build Linux binary only
build_linux() {
    print_info "Building Linux binary with YARA support..."
    
    cd "$PROJECT_ROOT"
    mkdir -p bin
    
    docker build \
        --target binaries \
        --output type=local,dest=./bin \
        -f docker/Dockerfile.builder \
        .
    
    if [ -f "bin/fastfinder-linux-amd64" ]; then
        print_success "Linux binary built successfully!"
        print_info "Binary: bin/fastfinder-linux-amd64"
        chmod +x bin/fastfinder-linux-amd64
        ls -lh bin/fastfinder-linux-amd64
    else
        print_error "Build failed!"
        exit 1
    fi
}

# Build Windows binary only
build_windows() {
    print_info "Building Windows binary with YARA support..."
    
    cd "$PROJECT_ROOT"
    mkdir -p bin
    
    docker build \
        --target binaries \
        --output type=local,dest=./bin \
        -f docker/Dockerfile.windows-builder \
        .
    
    if [ -f "bin/fastfinder-windows-amd64.exe" ]; then
        print_success "Windows binary built successfully!"
        print_info "Binary: bin/fastfinder-windows-amd64.exe"
        ls -lh bin/fastfinder-windows-amd64.exe
    else
        print_error "Build failed!"
        exit 1
    fi
}

# Clean up Docker build cache
clean_docker() {
    print_warning "Cleaning up Docker build cache..."
    
    # Prune build cache
    print_info "Pruning Docker build cache..."
    docker builder prune -f
    
    print_success "Cleanup complete!"
}

# Main logic
case "${1:-help}" in
    build-binaries)
        build_binaries
        ;;
    build-linux)
        build_linux
        ;;
    build-windows)
        build_windows
        ;;
    clean)
        clean_docker
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_usage
        exit 1
        ;;
esac
