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
    && rm -rf /var/lib/apt/lists/*

# Copy build script
COPY build_s3_bench.sh /build/build_s3_bench.sh

# Fix CRLF + patch script
RUN sed -i 's/\r$//' /build/build_s3_bench.sh && \
    sed -i \
      -e 's/sudo //g' \
      -e '/Installing dependencies/,+15 s/^/# /' \
      /build/build_s3_bench.sh && \
    chmod +x /build/build_s3_bench.sh

# Run build ONCE
RUN bash /build/build_s3_bench.sh

# ================================
# Stage 2: Binary-only output
# ================================
FROM scratch AS output

COPY --from=builder /root/aws-s3-benchmark/s3_benchmark_static /s3_benchmark_static
