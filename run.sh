#!/bin/bash
set -e

export MINIO_ROOT_USER=minioadmin
export MINIO_ROOT_PASSWORD=minioadmin

# Start MinIO server
minio server /data --console-address ":9001" &
MINIO_PID=$!

sleep 5

# Setup mc alias and seed bucket
mc alias set local http://127.0.0.1:9000 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD
mc mb -p local/benchmark-bucket || true
mc cp -r /seed/testdata/* local/benchmark-bucket/ || true

echo "Seeded MinIO bucket with testdata."

# Run benchmark
echo "=== Starting AWS S3 Benchmark ==="
./s3_benchmark_static

wait $MINIO_PID
