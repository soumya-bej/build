#!/bin/bash
set -e

# AWS C S3 Async Upload/Download Benchmark Builder and Runner
# - Builds AWS C libraries statically on Fedora
# - Builds a benchmark tool that:
#   1. Uploads a 1 MB object to S3
#   2. Downloads that object N times asynchronously
#   3. Prints throughput and latency metrics

WORK_DIR="$HOME/aws-s3-benchmark"
BUILD_DIR="$WORK_DIR/build"
INSTALL_DIR="$WORK_DIR/install"
SRC_DIR="$WORK_DIR/src"

echo "=== AWS C S3 Async Benchmark Setup ==="
echo "Working directory: $WORK_DIR"

mkdir -p "$BUILD_DIR" "$INSTALL_DIR" "$SRC_DIR"

# Install dependencies (Fedora)
echo "Installing dependencies..."
sudo dnf install -y \
    gcc \
    gcc-c++ \
    cmake \
    git \
    openssl-devel \
    libcurl-devel \
    zlib-devel \
    glibc-static \
    libstdc++-static \
    libxml2-devel \
    libxml2-static \
    perl \
    go

cd "$SRC_DIR"

# Clone dependencies in correct order
echo "Cloning AWS C libraries..."
repos=(
    "aws-lc:https://github.com/aws/aws-lc.git"
    "s2n-tls:https://github.com/aws/s2n-tls.git"
    "aws-c-common:https://github.com/awslabs/aws-c-common.git"
    "aws-c-cal:https://github.com/awslabs/aws-c-cal.git"
    "aws-c-io:https://github.com/awslabs/aws-c-io.git"
    "aws-c-compression:https://github.com/awslabs/aws-c-compression.git"
    "aws-c-http:https://github.com/awslabs/aws-c-http.git"
    "aws-c-sdkutils:https://github.com/awslabs/aws-c-sdkutils.git"
    "aws-c-auth:https://github.com/awslabs/aws-c-auth.git"
    "aws-checksums:https://github.com/awslabs/aws-checksums.git"
    "aws-c-s3:https://github.com/awslabs/aws-c-s3.git"
)

for repo in "${repos[@]}"; do
    name="${repo%%:*}"
    url="${repo#*:}"
    if [ ! -d "$name" ]; then
        git clone --depth 1 "$url"
    fi
done

# Function to build a library
build_library() {
    local lib_name=$1
    echo "Building $lib_name..."

    cd "$SRC_DIR/$lib_name"
    rm -rf build
    mkdir build
    cd build

    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
        -DCMAKE_PREFIX_PATH="$INSTALL_DIR" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTING=OFF

    make -j"$(nproc)"
    make install
}

# Build all libraries in order
for repo in "${repos[@]}"; do
    name="${repo%%:*}"
    build_library "$name"
done

# Create benchmark C program
echo "Creating async upload/download benchmark program..."
cat > "$WORK_DIR/s3_benchmark.c" << 'EOFCODE'
#include <aws/auth/credentials.h>
#include <aws/common/allocator.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/s3/s3_client.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BENCH_OBJECT_SIZE (1024 * 1024) /* 1 MB */

struct app_ctx {
    struct aws_allocator *allocator;
    struct aws_mutex mutex;
    struct aws_condition_variable cv;
    int active_requests;
    size_t successful_requests;
    size_t failed_requests;
    size_t total_bytes;
    uint64_t total_latency_ns;
    uint64_t min_latency_ns;
    uint64_t max_latency_ns;
};

struct transfer_ctx {
    struct app_ctx *app;
    uint64_t start_time;
    size_t bytes_transferred;
    char object_key[1024];
};

/* ========================= UTIL / USAGE ========================= */

static void print_usage(const char *prog_name) {
    fprintf(stderr,
        "Usage: %s --bucket <bucket> --region <region> "
        "--access-key <key> --secret-key <secret> [OPTIONS]\n\n",
        prog_name);
    fprintf(stderr, "Required:\n");
    fprintf(stderr, "  --bucket         S3 bucket name\n");
    fprintf(stderr, "  --region         AWS region\n");
    fprintf(stderr, "  --access-key     AWS access key\n");
    fprintf(stderr, "  --secret-key     AWS secret key\n\n");
    fprintf(stderr, "Optional:\n");
    fprintf(stderr, "  --object-key     S3 object key to use (default: s3-bench-1mb.bin)\n");
    fprintf(stderr, "  --count          Number of async download requests (default: 100)\n");
    fprintf(stderr, "  --concurrency    Max in-flight requests (default: same as count)\n");
    fprintf(stderr, "Note:\n");
    fprintf(stderr, "  - This tool uploads a 1 MB object and then downloads it multiple times.\n");
    fprintf(stderr, "  - Set AWS_ENDPOINT_URL for custom endpoints (MinIO, etc.).\n");
}

/* ========================= CALLBACKS ========================= */

static int on_body_received(struct aws_s3_meta_request *meta_request,
                            const struct aws_byte_cursor *body,
                            uint64_t range_start,
                            void *user_data) {
    (void)meta_request;
    (void)range_start;
    struct transfer_ctx *ctx = user_data;
    ctx->bytes_transferred += body->len;
    return AWS_OP_SUCCESS;
}

static void on_request_finished(struct aws_s3_meta_request *meta_request,
                                const struct aws_s3_meta_request_result *result,
                                void *user_data) {
    struct transfer_ctx *ctx = user_data;
    struct app_ctx *app = ctx->app;

    uint64_t end_time = 0;
    aws_high_res_clock_get_ticks(&end_time);
    uint64_t latency = end_time - ctx->start_time;

    aws_mutex_lock(&app->mutex);
    if (result->error_code == AWS_ERROR_SUCCESS) {
        app->successful_requests++;
        app->total_bytes += ctx->bytes_transferred;
        app->total_latency_ns += latency;
        if (latency < app->min_latency_ns) app->min_latency_ns = latency;
        if (latency > app->max_latency_ns) app->max_latency_ns = latency;
        printf("✓ %s (%zu bytes, %.2f ms)\n",
               ctx->object_key,
               ctx->bytes_transferred,
               latency / 1e6);
    } else {
        app->failed_requests++;
        fprintf(stderr, "✗ %s - Error: %s\n",
                ctx->object_key,
                aws_error_str(result->error_code));
    }

    app->active_requests--;
    aws_condition_variable_notify_one(&app->cv);
    aws_mutex_unlock(&app->mutex);

    aws_mem_release(app->allocator, ctx);
    aws_s3_meta_request_release(meta_request);
}

/* Separate callback for upload (we don't care about body) */
static int on_upload_body(struct aws_s3_meta_request *meta_request,
                          const struct aws_byte_cursor *body,
                          uint64_t range_start,
                          void *user_data) {
    (void)meta_request;
    (void)body;
    (void)range_start;
    (void)user_data;
    return AWS_OP_SUCCESS;
}

static void on_upload_finished(struct aws_s3_meta_request *meta_request,
                               const struct aws_s3_meta_request_result *result,
                               void *user_data) {
    struct transfer_ctx *ctx = user_data;
    struct app_ctx *app = ctx->app;

    uint64_t end_time = 0;
    aws_high_res_clock_get_ticks(&end_time);
    uint64_t latency = end_time - ctx->start_time;

    aws_mutex_lock(&app->mutex);
    if (result->error_code == AWS_ERROR_SUCCESS) {
        app->successful_requests++;
        app->total_bytes += ctx->bytes_transferred;
        app->total_latency_ns += latency;
        if (latency < app->min_latency_ns) app->min_latency_ns = latency;
        if (latency > app->max_latency_ns) app->max_latency_ns = latency;
        printf("UPLOAD ✓ %s (%zu bytes, %.2f ms)\n",
               ctx->object_key,
               ctx->bytes_transferred,
               latency / 1e6);
    } else {
        app->failed_requests++;
        fprintf(stderr, "UPLOAD ✗ %s - Error: %s\n",
                ctx->object_key,
                aws_error_str(result->error_code));
    }

    app->active_requests--;
    aws_condition_variable_notify_one(&app->cv);
    aws_mutex_unlock(&app->mutex);

    aws_mem_release(app->allocator, ctx);
    aws_s3_meta_request_release(meta_request);
}

/* ========================= MAIN ========================= */

int main(int argc, char *argv[]) {
    const char *bucket_name = NULL;
    const char *region = NULL;
    const char *access_key = NULL;
    const char *secret_key = NULL;
    const char *object_key = "s3-bench-1mb.bin";
    int count = 100;
    int concurrency = -1;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--bucket") == 0) && i + 1 < argc) {
            bucket_name = argv[++i];
        } else if ((strcmp(argv[i], "--region") == 0) && i + 1 < argc) {
            region = argv[++i];
        } else if ((strcmp(argv[i], "--access-key") == 0) && i + 1 < argc) {
            access_key = argv[++i];
        } else if ((strcmp(argv[i], "--secret-key") == 0) && i + 1 < argc) {
            secret_key = argv[++i];
        } else if ((strcmp(argv[i], "--object-key") == 0) && i + 1 < argc) {
            object_key = argv[++i];
        } else if ((strcmp(argv[i], "--count") == 0) && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if ((strcmp(argv[i], "--concurrency") == 0) && i + 1 < argc) {
            concurrency = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (!bucket_name || !region || !access_key || !secret_key) {
        print_usage(argv[0]);
        return 1;
    }
    if (count <= 0) {
        fprintf(stderr, "--count must be > 0\n");
        return 1;
    }
    if (concurrency <= 0) {
        concurrency = count; /* default: fully saturated with count requests */
    }

    printf("=== AWS C S3 Async Upload/Download Benchmark ===\n");
    printf("Bucket:      %s\n", bucket_name);
    printf("Region:      %s\n", region);
    printf("Object key:  %s\n", object_key);
    printf("Count:       %d\n", count);
    printf("Concurrency: %d\n\n", concurrency);

    struct aws_allocator *allocator = aws_default_allocator();
    aws_s3_library_init(allocator);

    struct app_ctx app = {
        .allocator = allocator,
        .min_latency_ns = UINT64_MAX,
    };
    aws_mutex_init(&app.mutex);
    aws_condition_variable_init(&app.cv);

    /* Event loop / networking setup (async) */
    struct aws_event_loop_group *el_group =
        aws_event_loop_group_new_default(allocator, 0, NULL);
    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 8,
    };
    struct aws_host_resolver *resolver =
        aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = el_group,
        .host_resolver = resolver,
    };
    struct aws_client_bootstrap *bootstrap =
        aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_tls_ctx_options tls_options;
    aws_tls_ctx_options_init_default_client(&tls_options, allocator);
    struct aws_tls_ctx *tls_ctx =
        aws_tls_client_ctx_new(allocator, &tls_options);
    struct aws_tls_connection_options tls_conn_options;
    aws_tls_connection_options_init_from_ctx(&tls_conn_options, tls_ctx);

    struct aws_credentials_provider_static_options cred_options = {
        .access_key_id = aws_byte_cursor_from_c_str(access_key),
        .secret_access_key = aws_byte_cursor_from_c_str(secret_key),
    };
    struct aws_credentials_provider *cred_provider =
        aws_credentials_provider_new_static(allocator, &cred_options);

    struct aws_signing_config_aws signing_config;
    AWS_ZERO_STRUCT(signing_config);
    signing_config.algorithm = AWS_SIGNING_ALGORITHM_V4;
    signing_config.signature_type = AWS_ST_HTTP_REQUEST_HEADERS;
    signing_config.region = aws_byte_cursor_from_c_str(region);
    signing_config.service = aws_byte_cursor_from_c_str("s3");
    signing_config.credentials_provider = cred_provider;
    signing_config.signed_body_value =
        aws_byte_cursor_from_c_str("UNSIGNED-PAYLOAD");
    signing_config.flags.use_double_uri_encode = false;

    struct aws_s3_client_config client_config;
    AWS_ZERO_STRUCT(client_config);
    client_config.client_bootstrap = bootstrap;
    client_config.region = aws_byte_cursor_from_c_str(region);
    client_config.tls_mode = AWS_MR_TLS_ENABLED;
    client_config.tls_connection_options = &tls_conn_options;
    client_config.signing_config = &signing_config;
    client_config.part_size = 8 * 1024 * 1024; /* 8 MB; overkill for 1 MB but OK */
    client_config.throughput_target_gbps = 10.0;

    struct aws_s3_client *client = aws_s3_client_new(allocator, &client_config);
    if (!client) {
        fprintf(stderr, "Failed to create S3 client\n");
        goto cleanup;
    }

    /* Prepare 1 MB payload in memory (no need for disk file) */
    uint8_t *payload = aws_mem_acquire(allocator, BENCH_OBJECT_SIZE);
    if (!payload) {
        fprintf(stderr, "Failed to allocate upload buffer\n");
        goto cleanup;
    }
    /* Fill with deterministic pattern */
    for (size_t i = 0; i < BENCH_OBJECT_SIZE; ++i) {
        payload[i] = (uint8_t)(i & 0xFF);
    }
    struct aws_byte_cursor payload_cursor =
        aws_byte_cursor_from_array(payload, BENCH_OBJECT_SIZE);

    printf("Uploading 1 MB object '%s'...\n", object_key);

    /* Construct PUT request */
    char upload_path[2048];
    snprintf(upload_path, sizeof(upload_path), "/%s/%s", bucket_name, object_key);

    struct aws_http_message *put_message =
        aws_http_message_new_request(allocator);
    aws_http_message_set_request_method(
        put_message, aws_byte_cursor_from_c_str("PUT"));
    aws_http_message_set_request_path(
        put_message, aws_byte_cursor_from_c_str(upload_path));

    /* Set Content-Length header */
    char content_length_buf[64];
    snprintf(content_length_buf, sizeof(content_length_buf), "%zu",
             (size_t)BENCH_OBJECT_SIZE);
    struct aws_http_header content_length_header = {
        .name = aws_byte_cursor_from_c_str("Content-Length"),
        .value = aws_byte_cursor_from_c_str(content_length_buf),
    };
    aws_http_message_add_header(put_message, content_length_header);

    /* Set body stream */
    struct aws_input_stream *input_stream =
        aws_input_stream_new_from_cursor(allocator, &payload_cursor);
    aws_http_message_set_body_stream(put_message, input_stream);

    /* Upload context */
    struct transfer_ctx *upload_ctx =
        aws_mem_calloc(allocator, 1, sizeof(struct transfer_ctx));
    upload_ctx->app = &app;
    upload_ctx->bytes_transferred = BENCH_OBJECT_SIZE;
    strncpy(upload_ctx->object_key, object_key,
            sizeof(upload_ctx->object_key) - 1);

    struct aws_s3_meta_request_options put_options;
    AWS_ZERO_STRUCT(put_options);
    put_options.type = AWS_S3_META_REQUEST_TYPE_PUT_OBJECT;
    put_options.message = put_message;
    put_options.body_callback = on_upload_body;
    put_options.finish_callback = on_upload_finished;
    put_options.user_data = upload_ctx;

    aws_high_res_clock_get_ticks(&upload_ctx->start_time);
    aws_mutex_lock(&app.mutex);
    app.active_requests++;
    aws_mutex_unlock(&app.mutex);

    struct aws_s3_meta_request *put_meta =
        aws_s3_client_make_meta_request(client, &put_options);
    if (!put_meta) {
        fprintf(stderr, "Failed to start PUT meta request\n");
        aws_mutex_lock(&app.mutex);
        app.active_requests--;
        app.failed_requests++;
        aws_mutex_unlock(&app.mutex);
        aws_mem_release(allocator, upload_ctx);
        aws_http_message_release(put_message);
        aws_input_stream_destroy(input_stream);
        goto cleanup;
    }
    aws_http_message_release(put_message);
    aws_input_stream_destroy(input_stream);

    /* Wait for upload to finish */
    aws_mutex_lock(&app.mutex);
    while (app.active_requests > 0) {
        aws_condition_variable_wait(&app.cv, &app.mutex);
    }
    aws_mutex_unlock(&app.mutex);

    if (app.failed_requests > 0) {
        fprintf(stderr, "Upload failed, aborting benchmark.\n");
        goto cleanup;
    }

    printf("\nUpload complete. Starting async download benchmark...\n");

    uint64_t benchmark_start = 0;
    aws_high_res_clock_get_ticks(&benchmark_start);

    int inflight = 0;
    app.total_bytes = 0;
    app.total_latency_ns = 0;
    app.min_latency_ns = UINT64_MAX;
    app.max_latency_ns = 0;
    app.successful_requests = 0;
    app.failed_requests = 0;

    /* Issue up to 'count' GET requests, with 'concurrency' cap */
    int launched = 0;
    while (launched < count) {
        /* Throttle in-flight requests */
        aws_mutex_lock(&app.mutex);
        while (app.active_requests >= concurrency) {
            aws_condition_variable_wait(&app.cv, &app.mutex);
        }
        app.active_requests++;
        inflight = app.active_requests;
        aws_mutex_unlock(&app.mutex);

        (void)inflight; /* not strictly needed, but useful for debugging */

        struct transfer_ctx *ctx =
            aws_mem_calloc(allocator, 1, sizeof(struct transfer_ctx));
        ctx->app = &app;
        strncpy(ctx->object_key, object_key,
                sizeof(ctx->object_key) - 1);

        char get_path[2048];
        snprintf(get_path, sizeof(get_path), "/%s/%s",
                 bucket_name, ctx->object_key);

        struct aws_http_message *get_message =
            aws_http_message_new_request(allocator);
        aws_http_message_set_request_method(
            get_message, aws_byte_cursor_from_c_str("GET"));
        aws_http_message_set_request_path(
            get_message, aws_byte_cursor_from_c_str(get_path));

        struct aws_s3_meta_request_options get_options;
        AWS_ZERO_STRUCT(get_options);
        get_options.type = AWS_S3_META_REQUEST_TYPE_GET_OBJECT;
        get_options.message = get_message;
        get_options.body_callback = on_body_received;
        get_options.finish_callback = on_request_finished;
        get_options.user_data = ctx;

        aws_high_res_clock_get_ticks(&ctx->start_time);
        struct aws_s3_meta_request *get_meta =
            aws_s3_client_make_meta_request(client, &get_options);
        if (!get_meta) {
            fprintf(stderr, "Failed to start GET meta request\n");
            aws_mutex_lock(&app.mutex);
            app.active_requests--;
            app.failed_requests++;
            aws_condition_variable_notify_one(&app.cv);
            aws_mutex_unlock(&app.mutex);
            aws_mem_release(allocator, ctx);
        }
        aws_http_message_release(get_message);

        launched++;
    }

    /* Wait for all GET requests to finish */
    aws_mutex_lock(&app.mutex);
    while (app.active_requests > 0) {
        aws_condition_variable_wait(&app.cv, &app.mutex);
    }
    aws_mutex_unlock(&app.mutex);

    uint64_t benchmark_end = 0;
    aws_high_res_clock_get_ticks(&benchmark_end);

    double total_time_sec =
        (double)(benchmark_end - benchmark_start) / 1e9;
    double total_mb = (app.total_bytes / (1024.0 * 1024.0));
    double throughput_mbps = total_time_sec > 0.0
                                 ? total_mb / total_time_sec
                                 : 0.0;
    double avg_latency_ms = app.successful_requests > 0
                                ? (app.total_latency_ns /
                                   (double)app.successful_requests) /
                                      1e6
                                : 0.0;
    size_t total_attempts =
        app.successful_requests + app.failed_requests;
    double success_rate = total_attempts > 0
                              ? (app.successful_requests * 100.0) /
                                    total_attempts
                              : 0.0;

    printf("\n=====================================\n");
    printf("       BENCHMARK RESULTS\n");
    printf("=====================================\n");
    printf("Object size:             %zu bytes (%.2f MB)\n",
           (size_t)BENCH_OBJECT_SIZE,
           (double)BENCH_OBJECT_SIZE / (1024.0 * 1024.0));
    printf("Total requests:          %zu\n", total_attempts);
    printf("Successful requests:     %zu\n", app.successful_requests);
    printf("Failed requests:         %zu\n", app.failed_requests);
    printf("Success rate:            %.1f%%\n", success_rate);
    printf("Total bytes transferred: %zu (%.2f MB)\n",
           app.total_bytes, total_mb);
    printf("Total time:              %.3f seconds\n",
           total_time_sec);
    printf("Throughput:              %.2f MB/s\n",
           throughput_mbps);
    printf("Average latency:         %.2f ms\n",
           avg_latency_ms);
    if (app.min_latency_ns != UINT64_MAX) {
        printf("Min latency:             %.2f ms\n",
               app.min_latency_ns / 1e6);
        printf("Max latency:             %.2f ms\n",
               app.max_latency_ns / 1e6);
    }
    printf("=====================================\n");

cleanup:
    if (client) {
        aws_s3_client_release(client);
    }
    if (cred_provider) {
        aws_credentials_provider_release(cred_provider);
    }
    aws_tls_connection_options_clean_up(&tls_conn_options);
    if (tls_ctx) {
        aws_tls_ctx_release(tls_ctx);
    }
    aws_tls_ctx_options_clean_up(&tls_options);
    if (bootstrap) {
        aws_client_bootstrap_release(bootstrap);
    }
    if (resolver) {
        aws_host_resolver_release(resolver);
    }
    if (el_group) {
        aws_event_loop_group_release(el_group);
    }
    aws_mutex_clean_up(&app.mutex);
    aws_condition_variable_clean_up(&app.cv);
    if (payload) {
        aws_mem_release(allocator, payload);
    }
    aws_s3_library_clean_up();
    return app.failed_requests > 0 ? 1 : 0;
}
EOFCODE

# Find all library paths and list what's available
echo "Locating libraries..."
echo "Contents of install directories:"
for dir in "$INSTALL_DIR/lib" "$INSTALL_DIR/lib64"; do
    if [ -d "$dir" ]; then
        echo "  $dir:"
        ls -la "$dir"/*.a 2>/dev/null | awk '{print "    " $9}' || echo "    (no .a files)"
    fi
done

echo ""
echo "Compiling benchmark program..."
gcc -o "$WORK_DIR/s3_benchmark_static" "$WORK_DIR/s3_benchmark.c" \
    -I"$INSTALL_DIR/include" \
    -L"$INSTALL_DIR/lib" \
    -L"$INSTALL_DIR/lib64" \
    -laws-c-s3 \
    -laws-c-auth \
    -laws-checksums \
    -laws-c-http \
    -laws-c-io \
    -laws-c-compression \
    -laws-c-cal \
    -laws-c-sdkutils \
    -laws-c-common \
    -ls2n \
    -lcrypto \
    -lssl \
    -lcurl \
    -lz \
    -lm \
    -lpthread \
    -ldl \
    -O3 2>&1 | tee /tmp/compile.log

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo ""
    echo "Compilation failed. Checking for aws-lc libraries..."
    find "$INSTALL_DIR" -name "*.a" | grep -E "(crypto|ssl|aws-lc)" | head -20
    echo ""
    echo "Try alternative linking order..."
    gcc -o "$WORK_DIR/s3_benchmark_static" "$WORK_DIR/s3_benchmark.c" \
        -I"$INSTALL_DIR/include" \
        -L"$INSTALL_DIR/lib" \
        -L"$INSTALL_DIR/lib64" \
        -Wl,--start-group \
        -laws-c-s3 \
        -laws-c-auth \
        -laws-checksums \
        -laws-c-http \
        -laws-c-io \
        -laws-c-compression \
        -laws-c-cal \
        -laws-c-sdkutils \
        -laws-c-common \
        -ls2n \
        "$INSTALL_DIR"/lib*/libcrypto.a \
        "$INSTALL_DIR"/lib*/libssl.a \
        -Wl,--end-group \
        -lcurl \
        -lz \
        -lm \
        -lpthread \
        -ldl \
        -O3
fi

echo ""
echo "=== Build Complete (Async Upload/Download Benchmark) ==="
echo "Binary: $WORK_DIR/s3_benchmark_static"
echo ""
echo "Example run:"
echo "  ./s3_benchmark_static --bucket my-bucket --region us-east-1 \\"
echo "    --access-key AKIAXXXXX --secret-key secretXXXX --count 500"
echo ""
echo "For custom endpoints (MinIO, etc.):"
echo "  export AWS_ENDPOINT_URL=https://minio.example.com:9000"
echo "  ./s3_benchmark_static --bucket my-bucket --region us-east-1 \\"
echo "    --access-key minioadmin --secret-key minioadmin --count 500"
