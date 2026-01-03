# FastFinder Docker Makefile
# Simplifies Docker operations

.PHONY: help build-binaries build-linux build-windows test

# Default target
help:
	@echo "FastFinder Docker Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make build-binaries    - Build both Linux and Windows 64-bit binaries"
	@echo "  make build-linux       - Build Linux binary with YARA support"
	@echo "  make build-windows     - Build Windows binary with YARA support"
	@echo "  make test              - Test Docker builds"
	@echo "  make clean             - Remove all Docker resources"
	@echo ""
	@echo "Examples:"
	@echo "  make build-binaries"
	@echo "  make build-linux"
	@echo "  make build-windows"

# Build both binaries (Linux and Windows)
build-binaries: build-linux build-windows
	@echo "✓ Both binaries built successfully!"
	@ls -lh ../bin/fastfinder-*

# Build Linux binary with YARA support
build-linux:
	@echo "Building Linux binary with YARA support..."
	@mkdir -p ../bin
	docker build \
		--target binaries \
		--output type=local,dest=../bin \
		-f Dockerfile.builder \
		..
	@echo "✓ Linux binary built: ../bin/fastfinder-linux-amd64"

# Build Windows binary with YARA support  
build-windows:
	@echo "Building Windows binary with YARA support..."
	@mkdir -p ../bin
	docker build \
		--target binaries \
		--output type=local,dest=../bin \
		-f Dockerfile.windows-builder \
		..
	@echo "✓ Windows binary built: ../bin/fastfinder-windows-amd64.exe"

# Test builds
test:
	@echo "Testing Linux builder Dockerfile..."
	docker build -f Dockerfile.builder --target linux-builder .. && \
	echo "✓ Linux builder test passed"
	@echo "Testing Windows builder Dockerfile..."
	docker build -f Dockerfile.windows-builder .. && \
	echo "✓ Windows builder test passed"
	@echo "✓ All tests passed"

# Clean up Docker resources
clean:
	@echo "Cleaning up Docker resources..."
	-docker ps -a | grep fastfinder | awk '{print $$1}' | xargs docker rm -f 2>/dev/null
	-docker images | grep fastfinder | awk '{print $$3}' | xargs docker rmi -f 2>/dev/null
	-docker builder prune -f
	@echo "✓ Cleanup complete"

# Remove binaries
clean-binaries:
	@echo "Removing built binaries..."
	rm -rf ../bin/fastfinder-*
	@echo "✓ Binaries removed"

# Full clean
clean-all: clean clean-binaries
	@echo "✓ Full cleanup complete"

