FROM ubuntu:22.04

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libxml2 libssl3 zlib1g curl bash wget unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install MinIO server
RUN wget https://dl.min.io/server/minio/release/linux-amd64/minio -O /usr/local/bin/minio \
    && chmod +x /usr/local/bin/minio

# Install MinIO client (mc)
RUN wget https://dl.min.io/client/mc/release/linux-amd64/mc -O /usr/local/bin/mc \
    && chmod +x /usr/local/bin/mc

# Copy benchmark binary and seed data
COPY s3_benchmark_static /app/s3_benchmark_static
COPY seed /seed
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

# Expose ports
EXPOSE 9000 9001

# Run MinIO, seed bucket, and benchmark
CMD ["/app/run.sh"]
