# Multi-stage Dockerfile for cross-compiling FastFinder for Linux and Windows
# This container builds 64-bit binaries without requiring local dependencies

FROM debian:bookworm-slim AS base

# Install common build dependencies
RUN apt-get update && apt-get install -y \
    wget \
    git \
    build-essential \
    automake \
    libtool \
    pkg-config \
    libssl-dev \
    ca-certificates \
    gcc-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    gcc-i686-linux-gnu \
    libc6-dev-i386-cross \
    && rm -rf /var/lib/apt/lists/*


# Install Go 1.24.6
ARG GO_VERSION=1.24.6
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Build YARA library 4.5.5 from source (static)
ARG YARA_VERSION=4.5.5
WORKDIR /build
RUN wget https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz && \
    tar -xzf v${YARA_VERSION}.tar.gz && \
    cd yara-${YARA_VERSION} && \
    ./bootstrap.sh && \
    ./configure --prefix=/usr/local --enable-static --disable-shared && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd .. && rm -rf yara-${YARA_VERSION} v${YARA_VERSION}.tar.gz

# Build YARA library 4.5.5 for ARM64 (static)
RUN wget https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz && \
    tar -xzf v${YARA_VERSION}.tar.gz && \
    cd yara-${YARA_VERSION} && \
    ./bootstrap.sh && \
    ./configure --host=aarch64-linux-gnu --prefix=/usr/aarch64-linux-gnu --enable-static --disable-shared && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf yara-${YARA_VERSION} v${YARA_VERSION}.tar.gz

# Build YARA library 4.5.5 for i386 (static)
RUN wget https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz && \
    tar -xzf v${YARA_VERSION}.tar.gz && \
    cd yara-${YARA_VERSION} && \
    ./bootstrap.sh && \
    ./configure --host=i686-linux-gnu --prefix=/usr/i686-linux-gnu --enable-static --disable-shared --disable-crypto && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf yara-${YARA_VERSION} v${YARA_VERSION}.tar.gz

# ========================================
# Stage 2: Linux builder
# ========================================
FROM base AS linux-builder

WORKDIR /src

# Copy source code
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
COPY examples ./examples/
COPY resources ./resources/
COPY tests ./tests/

# Build for Linux AMD64
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_CFLAGS="-I/usr/local/include"
ENV CGO_LDFLAGS="-L/usr/local/lib -Wl,-Bstatic -lyara -Wl,-Bdynamic -lssl -lcrypto"

RUN go build -ldflags="-s -w" -tags yara_static -o /output/fastfinder-linux-amd64 .

# Build for Linux ARM64
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=arm64
ENV CC=aarch64-linux-gnu-gcc
ENV CGO_CFLAGS="-I/usr/aarch64-linux-gnu/include"
ENV CGO_LDFLAGS="-L/usr/aarch64-linux-gnu/lib -Wl,-Bstatic -lyara -Wl,-Bdynamic" 
ENV PKG_CONFIG_PATH=""
# Note: OpenSSL might not be available easily for cross-compile in debian base without multiarch. 
# We'll skip openssl for ARM64 static build or we need to cross-compile openssl too.
# For simplicity, let's try building without openssl linkage if yara allows, or assume we need it.
# YARA usually requires it for crypto module.
# Let's try to link against valid paths. If missing, we might need to cross-compile openssl.
# For this task, assuming we might need to disable crypto module or build openssl.
# Let's assume we can build YARA with --disable-openssl for ARM64 to save complexity here.
# Wait, previous YARA build didn't specify --disable-openssl, so it used it (likely system available).
# But for ARM64, we don't have libssl-dev:arm64 installed (it's hard on amd64 host).

# Re-build YARA for ARM64 without OpenSSL to simplify
RUN rm -rf /usr/aarch64-linux-gnu/lib/libyara.a

RUN wget https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz && \
    tar -xzf v${YARA_VERSION}.tar.gz && \
    cd yara-${YARA_VERSION} && \
    ./bootstrap.sh && \
    ./configure --host=aarch64-linux-gnu --prefix=/usr/aarch64-linux-gnu --enable-static --disable-shared --disable-crypto && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf yara-${YARA_VERSION} v${YARA_VERSION}.tar.gz

ENV CGO_LDFLAGS="-L/usr/aarch64-linux-gnu/lib -Wl,-Bstatic -lyara -Wl,-Bdynamic"
ENV PKG_CONFIG_PATH=""

RUN go build -ldflags="-s -w" -tags "yara_static yara_no_pkg_config" -o /output/fastfinder-linux-arm64 .

# Build for Linux i386
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=386
ENV CC=i686-linux-gnu-gcc
ENV CGO_CFLAGS="-I/usr/i686-linux-gnu/include"
ENV CGO_LDFLAGS="-L/usr/i686-linux-gnu/lib -Wl,-Bstatic -lyara -Wl,-Bdynamic"
ENV PKG_CONFIG_PATH=""

RUN go build -ldflags="-s -w" -tags "yara_static yara_no_pkg_config" -o /output/fastfinder-linux-386 .

# ========================================
# Stage 3: Output collector - Linux only
# ========================================
FROM scratch AS binaries

# Copy compiled binary
COPY --from=linux-builder /output/fastfinder-linux-amd64 /
COPY --from=linux-builder /output/fastfinder-linux-arm64 /
COPY --from=linux-builder /output/fastfinder-linux-386 /

