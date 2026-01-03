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

# ========================================
# Stage 3: Output collector - Linux only
# ========================================
FROM scratch AS binaries

# Copy compiled binary
COPY --from=linux-builder /output/fastfinder-linux-amd64 /

