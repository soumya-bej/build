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
#include <aws/auth/signing_config.h>
#include <aws/cal/cal.h>
#include <aws/common/allocator.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/error.h>
#include <aws/common/logging.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/http.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
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
    fprintf(stderr, "  --object-key     S3 object key (default: s3-bench-1mb.bin)\n");
    fprintf(stderr, "  --count          Number of async GETs (default: 100)\n");
    fprintf(stderr, "  --concurrency    Max in-flight GETs (default: same as count)\n");
    fprintf(stderr, "Notes:\n");
    fprintf(stderr, "  - Uploads a 1 MB object, then downloads it N times async.\n");
    fprintf(stderr, "  - Set AWS_ENDPOINT_URL for custom S3-compatible endpoints.\n");
}

/* ============ Common callback handler ============ */

static void on_request_finished_common(struct aws_s3_meta_request *meta_request,
                                       const struct aws_s3_meta_request_result *result,
                                       void *user_data,
                                       const char *label) {
    struct transfer_ctx *tctx = user_data;

    if (!tctx || !tctx->app) {
        fprintf(stderr, "%s finished with null ctx/app\n", label);
        if (meta_request) {
            aws_s3_meta_request_release(meta_request);
        }
        return;
    }

    struct app_ctx *app = tctx->app;
    uint64_t end_ns = 0;
    aws_high_res_clock_get_ticks(&end_ns);
    uint64_t latency = end_ns - tctx->start_time;

    aws_mutex_lock(&app->mutex);
    if (result->error_code == AWS_ERROR_SUCCESS) {
        app->successful_requests++;
        app->total_bytes += tctx->bytes_transferred;
        app->total_latency_ns += latency;
        if (latency < app->min_latency_ns) app->min_latency_ns = latency;
        if (latency > app->max_latency_ns) app->max_latency_ns = latency;

        printf("%s ✓ %s (%zu bytes, %.2f ms)\n",
               label,
               tctx->object_key,
               tctx->bytes_transferred,
               latency / 1e6);
    } else {
        app->failed_requests++;
        fprintf(stderr, "%s ✗ %s - Error: %s (%d)\n",
                label,
                tctx->object_key,
                aws_error_str(result->error_code),
                result->error_code);
    }

    app->active_requests--;
    aws_condition_variable_notify_one(&app->cv);
    aws_mutex_unlock(&app->mutex);

    aws_mem_release(app->allocator, tctx);
    if (meta_request) {
        aws_s3_meta_request_release(meta_request);
    }
}

static void on_upload_finished(struct aws_s3_meta_request *meta_request,
                               const struct aws_s3_meta_request_result *result,
                               void *user_data) {
    on_request_finished_common(meta_request, result, user_data, "PUT");
}

static void on_download_finished(struct aws_s3_meta_request *meta_request,
                                 const struct aws_s3_meta_request_result *result,
                                 void *user_data) {
    on_request_finished_common(meta_request, result, user_data, "GET");
}

/* Upload body callback (we ignore any body) */
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

/* Download body callback: count bytes */
static int on_download_body(struct aws_s3_meta_request *meta_request,
                            const struct aws_byte_cursor *body,
                            uint64_t range_start,
                            void *user_data) {
    (void)meta_request;
    (void)range_start;
    struct transfer_ctx *tctx = user_data;
    tctx->bytes_transferred += body->len;
    return AWS_OP_SUCCESS;
}

/* ============ Main ============ */

int main(int argc, char *argv[]) {
    const char *bucket_name = NULL;
    const char *region = NULL;
    const char *access_key = NULL;
    const char *secret_key = NULL;
    const char *object_key = "s3-bench-1mb.bin";
    int count = 100;
    int concurrency = -1;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--bucket") == 0 && i + 1 < argc) {
            bucket_name = argv[++i];
        } else if (strcmp(argv[i], "--region") == 0 && i + 1 < argc) {
            region = argv[++i];
        } else if (strcmp(argv[i], "--access-key") == 0 && i + 1 < argc) {
            access_key = argv[++i];
        } else if (strcmp(argv[i], "--secret-key") == 0 && i + 1 < argc) {
            secret_key = argv[++i];
        } else if (strcmp(argv[i], "--object-key") == 0 && i + 1 < argc) {
            object_key = argv[++i];
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--concurrency") == 0 && i + 1 < argc) {
            concurrency = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
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
        concurrency = count;
    }

    printf("=== AWS C S3 Async Upload/Download Benchmark ===\n");
    printf("Bucket:      %s\n", bucket_name);
    printf("Region:      %s\n", region);
    printf("Object key:  %s\n", object_key);
    printf("Count:       %d\n", count);
    printf("Concurrency: %d\n\n", concurrency);

    struct aws_allocator *allocator = aws_default_allocator();

    /* Global library init per AWS C SDK docs */
    aws_common_library_init(allocator);
    aws_cal_library_init(allocator);
    aws_io_library_init(allocator);
    aws_http_library_init(allocator);
    aws_s3_library_init(allocator);

    /* App context */
    struct app_ctx app;
    AWS_ZERO_STRUCT(app);
    app.allocator = allocator;
    app.min_latency_ns = UINT64_MAX;
    aws_mutex_init(&app.mutex);
    aws_condition_variable_init(&app.cv);

    /* Pointer handles; init to NULL for safe cleanup */
    struct aws_event_loop_group *el_group = NULL;
    struct aws_host_resolver *resolver = NULL;
    struct aws_client_bootstrap *bootstrap = NULL;
    struct aws_credentials_provider *cred_provider = NULL;
    struct aws_s3_client *client = NULL;
    uint8_t *payload = NULL;

    int exit_code = 1;

    /* Event loop group */
    el_group = aws_event_loop_group_new_default(allocator, 0, NULL);
    if (!el_group) {
        fprintf(stderr, "Failed to create event loop group: %s\n",
                aws_error_str(aws_last_error()));
        goto cleanup;
    }

    /* Host resolver */
    struct aws_host_resolver_default_options resolver_opts;
    AWS_ZERO_STRUCT(resolver_opts);
    resolver_opts.el_group = el_group;
    resolver_opts.max_entries = 8;
    resolver = aws_host_resolver_new_default(allocator, &resolver_opts);
    if (!resolver) {
        fprintf(stderr, "Failed to create host resolver: %s\n",
                aws_error_str(aws_last_error()));
        goto cleanup;
    }

    /* Client bootstrap */
    struct aws_client_bootstrap_options bootstrap_opts;
    AWS_ZERO_STRUCT(bootstrap_opts);
    bootstrap_opts.event_loop_group = el_group;
    bootstrap_opts.host_resolver = resolver;
    bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_opts);
    if (!bootstrap) {
        fprintf(stderr, "Failed to create client bootstrap: %s\n",
                aws_error_str(aws_last_error()));
        goto cleanup;
    }

    /* Static credentials provider (doc: aws_credentials_provider_new_static) */
    struct aws_credentials_provider_static_options cred_opts;
    AWS_ZERO_STRUCT(cred_opts);
    cred_opts.access_key_id = aws_byte_cursor_from_c_str(access_key);
    cred_opts.secret_access_key = aws_byte_cursor_from_c_str(secret_key);
    cred_provider = aws_credentials_provider_new_static(allocator, &cred_opts);
    if (!cred_provider) {
        fprintf(stderr, "Failed to create credentials provider: %s\n",
                aws_error_str(aws_last_error()));
        goto cleanup;
    }

    /* Signing config per docs */
    struct aws_signing_config_aws signing_cfg;
    AWS_ZERO_STRUCT(signing_cfg);
    signing_cfg.config_type = AWS_SIGNING_CONFIG_AWS;
    signing_cfg.algorithm = AWS_SIGNING_ALGORITHM_V4;
    signing_cfg.signature_type = AWS_ST_HTTP_REQUEST_HEADERS;
    signing_cfg.region = aws_byte_cursor_from_c_str(region);
    signing_cfg.service = aws_byte_cursor_from_c_str("s3");
    signing_cfg.credentials_provider = cred_provider;
    signing_cfg.signed_body_value = aws_byte_cursor_from_c_str("UNSIGNED-PAYLOAD");
    signing_cfg.flags.use_double_uri_encode = false;
    signing_cfg.flags.should_normalize_uri_path = true;

    /* S3 client configuration (doc: aws_s3_client_new) */
    struct aws_s3_client_config s3_cfg;
    AWS_ZERO_STRUCT(s3_cfg);
    s3_cfg.client_bootstrap = bootstrap;
    s3_cfg.region = aws_byte_cursor_from_c_str(region);
    s3_cfg.signing_config = &signing_cfg;
    /* for high throughput docs suggest setting both: */
    s3_cfg.part_size = 8 * 1024 * 1024;
    s3_cfg.throughput_target_gbps = 10.0;
    /* Use default endpoint from region or AWS_ENDPOINT_URL env var */

    client = aws_s3_client_new(allocator, &s3_cfg);
    if (!client) {
        fprintf(stderr, "Failed to create S3 client: %s\n",
                aws_error_str(aws_last_error()));
        goto cleanup;
    }

    /* Prepare 1 MB payload */
    payload = aws_mem_acquire(allocator, BENCH_OBJECT_SIZE);
    if (!payload) {
        fprintf(stderr, "Failed to allocate payload buffer\n");
        goto cleanup;
    }
    for (size_t i = 0; i < BENCH_OBJECT_SIZE; ++i) {
        payload[i] = (uint8_t)(i & 0xFF);
    }
    struct aws_byte_cursor payload_cursor =
        aws_byte_cursor_from_array(payload, BENCH_OBJECT_SIZE);

    /* ===== 1) Upload ===== */
    printf("Uploading 1 MB object '%s'...\n", object_key);

    char put_path[2048];
    snprintf(put_path, sizeof(put_path), "/%s/%s", bucket_name, object_key);

    struct aws_http_message *put_msg =
        aws_http_message_new_request(allocator);
    if (!put_msg) {
        fprintf(stderr, "Failed to create PUT message: %s\n",
                aws_error_str(aws_last_error()));
        goto cleanup;
    }

    aws_http_message_set_request_method(
        put_msg, aws_byte_cursor_from_c_str("PUT"));
    aws_http_message_set_request_path(
        put_msg, aws_byte_cursor_from_c_str(put_path));

    /* Content-Length header (docs: you must set it for bodies) */
    char len_buf[64];
    snprintf(len_buf, sizeof(len_buf), "%zu", (size_t)BENCH_OBJECT_SIZE);
    struct aws_http_header h_content_length = {
        .name = aws_byte_cursor_from_c_str("Content-Length"),
        .value = aws_byte_cursor_from_c_str(len_buf),
    };
    aws_http_message_add_header(put_msg, h_content_length);

    /* Body stream from cursor */
    struct aws_input_stream *put_body =
        aws_input_stream_new_from_cursor(allocator, &payload_cursor);
    if (!put_body) {
        fprintf(stderr, "Failed to create PUT body stream: %s\n",
                aws_error_str(aws_last_error()));
        aws_http_message_release(put_msg);
        goto cleanup;
    }
    aws_http_message_set_body_stream(put_msg, put_body);

    struct transfer_ctx *upload_ctx =
        aws_mem_calloc(allocator, 1, sizeof(struct transfer_ctx));
    if (!upload_ctx) {
        fprintf(stderr, "Failed to allocate upload ctx\n");
        aws_http_message_release(put_msg);
        aws_input_stream_destroy(put_body);
        goto cleanup;
    }
    upload_ctx->app = &app;
    upload_ctx->bytes_transferred = BENCH_OBJECT_SIZE;
    strncpy(upload_ctx->object_key, object_key,
            sizeof(upload_ctx->object_key) - 1);

    struct aws_s3_meta_request_options put_opts;
    AWS_ZERO_STRUCT(put_opts);
    put_opts.type = AWS_S3_META_REQUEST_TYPE_PUT_OBJECT;
    put_opts.message = put_msg;
    put_opts.body_callback = on_upload_body;
    put_opts.finish_callback = on_upload_finished;
    put_opts.user_data = upload_ctx;

    aws_high_res_clock_get_ticks(&upload_ctx->start_time);

    aws_mutex_lock(&app.mutex);
    app.active_requests++;
    aws_mutex_unlock(&app.mutex);

    struct aws_s3_meta_request *put_mr =
        aws_s3_client_make_meta_request(client, &put_opts);
    if (!put_mr) {
        fprintf(stderr, "Failed to start PUT meta request: %s\n",
                aws_error_str(aws_last_error()));
        aws_mutex_lock(&app.mutex);
        app.active_requests--;
        app.failed_requests++;
        aws_mutex_unlock(&app.mutex);

        aws_mem_release(allocator, upload_ctx);
        aws_http_message_release(put_msg);
        aws_input_stream_destroy(put_body);
        goto cleanup;
    }

    aws_http_message_release(put_msg);
    aws_input_stream_destroy(put_body);

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

    printf("\nUpload complete. Starting async download benchmark...\n\n");

    /* ===== 2) Async GET benchmark ===== */

    app.total_bytes = 0;
    app.total_latency_ns = 0;
    app.min_latency_ns = UINT64_MAX;
    app.max_latency_ns = 0;
    app.successful_requests = 0;
    app.failed_requests = 0;
    app.active_requests = 0;

    uint64_t bench_start_ns = 0;
    aws_high_res_clock_get_ticks(&bench_start_ns);

    int launched = 0;
    while (launched < count) {
        /* limit in-flight via condition variable */
        aws_mutex_lock(&app.mutex);
        while (app.active_requests >= concurrency) {
            aws_condition_variable_wait(&app.cv, &app.mutex);
        }
        app.active_requests++;
        aws_mutex_unlock(&app.mutex);

        struct transfer_ctx *tctx =
            aws_mem_calloc(allocator, 1, sizeof(struct transfer_ctx));
        if (!tctx) {
            fprintf(stderr, "Failed to allocate download ctx\n");
            aws_mutex_lock(&app.mutex);
            app.active_requests--;
            aws_mutex_unlock(&app.mutex);
            break;
        }

        tctx->app = &app;
        strncpy(tctx->object_key, object_key,
                sizeof(tctx->object_key) - 1);

        char get_path[2048];
        snprintf(get_path, sizeof(get_path), "/%s/%s",
                 bucket_name, tctx->object_key);

        struct aws_http_message *get_msg =
            aws_http_message_new_request(allocator);
        if (!get_msg) {
            fprintf(stderr, "Failed to create GET message: %s\n",
                    aws_error_str(aws_last_error()));
            aws_mem_release(allocator, tctx);
            aws_mutex_lock(&app.mutex);
            app.active_requests--;
            aws_mutex_unlock(&app.mutex);
            break;
        }

        aws_http_message_set_request_method(
            get_msg, aws_byte_cursor_from_c_str("GET"));
        aws_http_message_set_request_path(
            get_msg, aws_byte_cursor_from_c_str(get_path));

        struct aws_s3_meta_request_options get_opts;
        AWS_ZERO_STRUCT(get_opts);
        get_opts.type = AWS_S3_META_REQUEST_TYPE_GET_OBJECT;
        get_opts.message = get_msg;
        get_opts.body_callback = on_download_body;
        get_opts.finish_callback = on_download_finished;
        get_opts.user_data = tctx;

        aws_high_res_clock_get_ticks(&tctx->start_time);

        struct aws_s3_meta_request *get_mr =
            aws_s3_client_make_meta_request(client, &get_opts);
        if (!get_mr) {
            fprintf(stderr, "Failed to start GET meta request: %s\n",
                    aws_error_str(aws_last_error()));
            aws_http_message_release(get_msg);
            aws_mem_release(allocator, tctx);
            aws_mutex_lock(&app.mutex);
            app.active_requests--;
            app.failed_requests++;
            aws_condition_variable_notify_one(&app.cv);
            aws_mutex_unlock(&app.mutex);
            break;
        }

        aws_http_message_release(get_msg);
        launched++;
    }

    /* Wait for all GETs to complete */
    aws_mutex_lock(&app.mutex);
    while (app.active_requests > 0) {
        aws_condition_variable_wait(&app.cv, &app.mutex);
    }
    aws_mutex_unlock(&app.mutex);

    uint64_t bench_end_ns = 0;
    aws_high_res_clock_get_ticks(&bench_end_ns);

    size_t total_attempts = app.successful_requests + app.failed_requests;
    double total_time_s = (double)(bench_end_ns - bench_start_ns) / 1e9;
    double total_mb = app.total_bytes / (1024.0 * 1024.0);
    double throughput_mb_s = total_time_s > 0 ? total_mb / total_time_s : 0.0;
    double avg_latency_ms = app.successful_requests > 0
                                ? (app.total_latency_ns / (double)app.successful_requests) / 1e6
                                : 0.0;
    double success_rate = total_attempts > 0
                              ? (app.successful_requests * 100.0) / total_attempts
                              : 0.0;

    printf("=====================================\n");
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
    printf("Total time:              %.3f s\n", total_time_s);
    printf("Throughput:              %.2f MB/s\n", throughput_mb_s);
    printf("Average latency:         %.2f ms\n", avg_latency_ms);
    if (app.min_latency_ns != UINT64_MAX) {
        printf("Min latency:             %.2f ms\n",
               app.min_latency_ns / 1e6);
        printf("Max latency:             %.2f ms\n",
               app.max_latency_ns / 1e6);
    }
    printf("=====================================\n");

    exit_code = (app.failed_requests > 0) ? 1 : 0;

cleanup:
    if (client) {
        aws_s3_client_release(client);
    }
    if (cred_provider) {
        aws_credentials_provider_release(cred_provider);
    }
    if (bootstrap) {
        aws_client_bootstrap_release(bootstrap);
    }
    if (resolver) {
        aws_host_resolver_release(resolver);
    }
    if (el_group) {
        aws_event_loop_group_release(el_group);
    }
    if (payload) {
        aws_mem_release(allocator, payload);
    }

    aws_mutex_clean_up(&app.mutex);
    aws_condition_variable_clean_up(&app.cv);

    aws_s3_library_clean_up();
    aws_http_library_clean_up();
    aws_io_library_clean_up();
    aws_cal_library_clean_up();
    aws_common_library_clean_up();

    return exit_code;
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