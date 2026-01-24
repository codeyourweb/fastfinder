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
  build-runtime      Build the runtime image (FastFinder inside container)
  run-runtime        Run FastFinder inside a container named "runtime"
                     Options: --config=PATH --scan=PATH --interactive --triage
  clean              Remove FastFinder Docker resources
  help               Show this help message

Examples:
  # Build both Linux and Windows binaries
  $0 build-binaries

  # Build only Linux binary
  $0 build-linux

  # Build only Windows binary
  $0 build-windows

  # Build runtime image
  $0 build-runtime

  # Run FastFinder in container with config directory
  $0 run-runtime --config=/path/to/config --scan=/data

  # Run with specific config file
  $0 run-runtime --config=/path/to/config.yaml --scan=/data

  # Interactive shell mode
  $0 run-runtime --interactive

  # Triage mode (continuous monitoring)
  $0 run-runtime --config=/path/to/config --scan=/data --triage

  # Clean up FastFinder Docker resources
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
        print_success "All binaries built successfully!"
        print_info "Linux binaries (amd64/arm64/i386) and Windows binaries (amd64/arm64/i386) are in ./bin/"
        
        # Make Linux binaries executable
        chmod +x bin/fastfinder-linux-*
        
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
        print_success "Linux binaries built successfully!"
        print_info "Binaries are in ./bin/"
        chmod +x bin/fastfinder-linux-*
        ls -lh bin/fastfinder-linux-*
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
        print_success "Windows binaries built successfully!"
        print_info "Binaries are in ./bin/"
        ls -lh bin/fastfinder-windows-*
    else
        print_error "Build failed!"
        exit 1
    fi
}

# Build runtime image
build_runtime() {
    print_info "Building FastFinder runtime image..."
    
    cd "$PROJECT_ROOT"
    
    docker build \
        -f docker/Dockerfile.runtime \
        -t fastfinder:runtime \
        .
    
    print_success "Runtime image built as fastfinder:runtime"
}

# Run FastFinder in runtime container
run_runtime() {
    local config_path="$PROJECT_ROOT/examples"
    local scan_path="$PROJECT_ROOT"
    local interactive=false
    local triage=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config=*)
                config_path="${1#*=}"
                shift
                ;;
            --scan=*)
                scan_path="${1#*=}"
                shift
                ;;
            --interactive)
                interactive=true
                shift
                ;;
            --triage)
                triage=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    # Ensure runtime image exists
    if ! docker image inspect fastfinder:runtime >/dev/null 2>&1; then
        build_runtime
    fi
    
    # Check config path exists
    if [ ! -e "$config_path" ]; then
        print_error "Config path not found: $config_path"
        return 1
    fi
    
    # Resolve paths
    config_path=$(realpath "$config_path")
    
    local config_file_in_container="/config/config.yml"
    local host_config_dir
    
    if [ -d "$config_path" ]; then
        host_config_dir="$config_path"
        print_info "Config mode: directory mounting - looking for config.yml in $config_path"
    else
        host_config_dir=$(dirname "$config_path")
        config_file_in_container="/config/$(basename "$config_path")"
        print_info "Config mode: file mounting - using $(basename "$config_path") from $host_config_dir"
    fi
    
    # Resolve scan path if not Linux-style
    if [[ ! "$scan_path" =~ ^/ ]]; then
        if [ ! -e "$scan_path" ]; then
            print_error "Scan path not found: $scan_path"
            return 1
        fi
        scan_path=$(realpath "$scan_path")
    fi
    
    print_info "Running FastFinder in container 'runtime' (privileged for drive discovery)..."
    
    # Remove existing container if present
    docker rm -f runtime >/dev/null 2>&1 || true
    
    # Build docker run command
    local docker_cmd=(docker run --rm -it --name runtime --privileged --pid=host)
    docker_cmd+=(--cap-add SYS_ADMIN --cap-add SYS_RAWIO)
    docker_cmd+=(-e "FASTFINDER_DISABLE_MUTEX=1")
    docker_cmd+=(-v "${host_config_dir}:/config")
    docker_cmd+=(-v "${scan_path}:/scan:ro")
    
    if [ "$interactive" = true ]; then
        docker_cmd+=(--entrypoint /bin/bash fastfinder:runtime)
    else
        docker_cmd+=(fastfinder:runtime -c "$config_file_in_container")
        if [ "$triage" = true ]; then
            docker_cmd+=(-t)
            print_info "Triage mode enabled - continuous monitoring active"
        fi
    fi
    
    "${docker_cmd[@]}"
}

# Clean up Docker build cache
clean_docker() {
    print_warning "Cleaning up FastFinder Docker resources..."
    
    # Remove FastFinder runtime containers
    print_info "Removing FastFinder containers..."
    local containers=$(docker ps -a --filter "name=runtime" --format "{{.ID}}" 2>/dev/null || true)
    if [ -n "$containers" ]; then
        docker rm -f $containers >/dev/null 2>&1 || true
        print_success "Removed FastFinder containers"
    else
        print_info "No FastFinder containers found"
    fi
    
    # Remove FastFinder images
    print_info "Removing FastFinder images..."
    local images=$(docker images --filter "reference=fastfinder:*" --format "{{.ID}}" 2>/dev/null || true)
    if [ -n "$images" ]; then
        docker rmi -f $images >/dev/null 2>&1 || true
        print_success "Removed FastFinder images"
    else
        print_info "No FastFinder images found"
    fi
    
    # Optional: prune all build cache (affects all projects!)
    print_warning "To clean ALL Docker build cache (all projects), run: docker builder prune -f"
    
    print_success "FastFinder cleanup complete!"
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
    build-runtime)
        build_runtime
        ;;
    run-runtime)
        shift
        run_runtime "$@"
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
