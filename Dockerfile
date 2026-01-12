# ================================
# Stage 1: Build (glibc 2.35)
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
    golang \
    libssl-dev \
    libcurl4-openssl-dev \
    zlib1g-dev \
    libxml2-dev \
    dos2unix \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Copy build script
COPY build_s3_bench.sh /build/build_s3_bench.sh

# Patch script:
# 1. Remove sudo
# 2. Comment dependency install section
# 3. Fix Windows CRLF
RUN sed -i \
    -e 's/sudo //g' \
    -e '/Installing dependencies/,+15 s/^/# /' \
    /build/build_s3_bench.sh \
    && dos2unix /build/build_s3_bench.sh \
    && chmod +x /build/build_s3_bench.sh

# Run build using bash (NOT sh)
RUN bash /build/build_s3_bench.sh

# ================================
# Stage 2: Binary-only output
# ================================
FROM scratch AS output

COPY --from=builder /root/aws-s3-benchmark/s3_benchmark_static /s3_benchmark_static
