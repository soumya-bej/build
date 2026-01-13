# ================================
# Stage 1: Build
# ================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    cmake \
    git \
    perl \
    curl \
    pkg-config \
    ca-certificates \
    golang-go \
    libssl-dev \
    libcurl4-openssl-dev \
    zlib1g-dev \
    libxml2-dev \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Verify Go installation
RUN go version

# Copy build script
COPY build_s3_bench.sh /build/build_s3_bench.sh

# Fix Windows line endings + patch script
RUN sed -i 's/\r$//' /build/build_s3_bench.sh && \
    sed -i \
      -e 's/sudo //g' \
      -e '/Installing dependencies/,+15 s/^/# /' \
      -e 's|WORK_DIR=.*|WORK_DIR=/build/aws-s3-benchmark|' \
      /build/build_s3_bench.sh && \
    chmod +x /build/build_s3_bench.sh

# Build the binary
RUN bash /build/build_s3_bench.sh

# Expose the built binary to a known location
RUN mkdir -p /build/output && \
    cp /build/aws-s3-benchmark/s3_benchmark_static /build/output/s3_benchmark_static

# ================================
# Stage 2: Optional minimal image
# ================================
FROM scratch AS runtime

COPY --from=builder /build/output/s3_benchmark_static /s3_benchmark_static
