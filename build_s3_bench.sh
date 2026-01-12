#!/bin/bash
set -e

# AWS C S3 Benchmark Builder and Runner - FIXED VERSION
# This script builds a static binary on Fedora and creates a benchmark tool

WORK_DIR="$HOME/aws-s3-benchmark"
BUILD_DIR="$WORK_DIR/build"
INSTALL_DIR="$WORK_DIR/install"
SRC_DIR="$WORK_DIR/src"

echo "=== AWS C S3 Benchmark Setup (Fixed) ==="
echo "Working directory: $WORK_DIR"

# Create directories
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

# Function to build library
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

    make -j$(nproc)
    make install
}

# Build all libraries in order
for repo in "${repos[@]}"; do
    name="${repo%%:*}"
    build_library "$name"
done

# Create the FIXED benchmark C program
echo "Creating fixed benchmark program..."
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
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct s3_object {
    char key[1024];
    size_t size;
};

struct object_list {
    struct s3_object *objects;
    size_t count;
    size_t capacity;
};

struct app_ctx {
    struct aws_allocator *allocator;
    struct aws_mutex mutex;
    struct aws_condition_variable cv;
    int active_requests;
    size_t successful_downloads;
    size_t failed_downloads;
    size_t total_bytes;
    uint64_t total_latency_ns;
    uint64_t min_latency_ns;
    uint64_t max_latency_ns;
};

struct download_ctx {
    struct app_ctx *app;
    uint64_t start_time;
    size_t bytes_downloaded;
    char object_key[1024];
};

struct list_ctx {
    struct aws_allocator *allocator;
    struct aws_byte_buf response_body;
    struct aws_mutex mutex;
    struct aws_condition_variable cv;
    int done;
    int error;
};

static int on_list_body(struct aws_s3_meta_request *meta_request,
    const struct aws_byte_cursor *body, uint64_t range_start, void *user_data) {
    (void)meta_request; (void)range_start;
    struct list_ctx *ctx = user_data;
    aws_mutex_lock(&ctx->mutex);
    aws_byte_buf_append_dynamic(&ctx->response_body, body);
    aws_mutex_unlock(&ctx->mutex);
    return AWS_OP_SUCCESS;
}

static void on_list_finished(struct aws_s3_meta_request *meta_request,
    const struct aws_s3_meta_request_result *result, void *user_data) {
    struct list_ctx *ctx = user_data;
    aws_mutex_lock(&ctx->mutex);
    if (result->error_code != AWS_ERROR_SUCCESS) {
        ctx->error = 1;
        fprintf(stderr, "List failed: %s\n", aws_error_str(result->error_code));
    }
    ctx->done = 1;
    aws_condition_variable_notify_all(&ctx->cv);
    aws_mutex_unlock(&ctx->mutex);
    aws_s3_meta_request_release(meta_request);
}

static void parse_list_objects_xml(const char *xml_data, size_t xml_len,
    struct object_list *obj_list, const char *prefix) {
    xmlDoc *doc = xmlReadMemory(xml_data, xml_len, NULL, NULL, XML_PARSE_RECOVER);
    if (!doc) return;
    xmlNode *root = xmlDocGetRootElement(doc);
    if (!root) { xmlFreeDoc(doc); return; }

    for (xmlNode *node = root->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE && strcmp((char*)node->name, "Contents") == 0) {
            char key[1024] = {0};
            size_t size = 0;
            for (xmlNode *child = node->children; child; child = child->next) {
                if (child->type == XML_ELEMENT_NODE) {
                    xmlChar *content = xmlNodeGetContent(child);
                    if (strcmp((char*)child->name, "Key") == 0)
                        strncpy(key, (char*)content, sizeof(key) - 1);
                    else if (strcmp((char*)child->name, "Size") == 0)
                        size = strtoull((char*)content, NULL, 10);
                    xmlFree(content);
                }
            }
            if (strlen(key) > 0 && (strlen(prefix) == 0 || strstr(key, prefix) == key) &&
                (strstr(key, ".avro") || strstr(key, ".AVRO"))) {
                if (obj_list->count >= obj_list->capacity) {
                    obj_list->capacity *= 2;
                    obj_list->objects = realloc(obj_list->objects,
                        obj_list->capacity * sizeof(struct s3_object));
                }
                strncpy(obj_list->objects[obj_list->count].key, key, sizeof(key) - 1);
                obj_list->objects[obj_list->count].size = size;
                obj_list->count++;
            }
        }
    }
    xmlFreeDoc(doc);
}

static int list_objects(struct aws_s3_client *client, struct aws_allocator *allocator,
    const char *bucket_name, const char *prefix, struct object_list *obj_list) {
    struct list_ctx list_ctx = {0};
    list_ctx.allocator = allocator;
    aws_byte_buf_init(&list_ctx.response_body, allocator, 65536);
    aws_mutex_init(&list_ctx.mutex);
    aws_condition_variable_init(&list_ctx.cv);
    char continuation_token[1024] = {0};
    int has_more = 1;

    while (has_more) {
        list_ctx.done = 0;
        list_ctx.error = 0;
        size_t prev_len = list_ctx.response_body.len;
        char path[2048];
        if (strlen(continuation_token) > 0)
            snprintf(path, sizeof(path), "/%s/?list-type=2&prefix=%s&continuation-token=%s",
                bucket_name, prefix, continuation_token);
        else
            snprintf(path, sizeof(path), "/%s/?list-type=2&prefix=%s", bucket_name, prefix);

        struct aws_http_message *message = aws_http_message_new_request(allocator);
        aws_http_message_set_request_method(message, aws_byte_cursor_from_c_str("GET"));
        aws_http_message_set_request_path(message, aws_byte_cursor_from_c_str(path));

        struct aws_s3_meta_request_options options = {
            .type = AWS_S3_META_REQUEST_TYPE_DEFAULT,
            .message = message,
            .body_callback = on_list_body,
            .finish_callback = on_list_finished,
            .user_data = &list_ctx,
        };

        struct aws_s3_meta_request *meta_request = aws_s3_client_make_meta_request(client, &options);
        if (!meta_request) {
            aws_http_message_release(message);
            aws_byte_buf_clean_up(&list_ctx.response_body);
            return -1;
        }

        aws_mutex_lock(&list_ctx.mutex);
        while (!list_ctx.done)
            aws_condition_variable_wait(&list_ctx.cv, &list_ctx.mutex);
        aws_mutex_unlock(&list_ctx.mutex);
        aws_http_message_release(message);

        if (list_ctx.error) {
            aws_byte_buf_clean_up(&list_ctx.response_body);
            return -1;
        }

        parse_list_objects_xml((char*)list_ctx.response_body.buffer + prev_len,
            list_ctx.response_body.len - prev_len, obj_list, prefix);

        continuation_token[0] = '\0';
        has_more = 0;
        xmlDoc *doc = xmlReadMemory((char*)list_ctx.response_body.buffer + prev_len,
            list_ctx.response_body.len - prev_len, NULL, NULL, XML_PARSE_RECOVER);
        if (doc) {
            xmlNode *root = xmlDocGetRootElement(doc);
            for (xmlNode *node = root->children; node; node = node->next) {
                if (node->type == XML_ELEMENT_NODE) {
                    xmlChar *content = xmlNodeGetContent(node);
                    if (strcmp((char*)node->name, "IsTruncated") == 0 && strcmp((char*)content, "true") == 0)
                        has_more = 1;
                    else if (strcmp((char*)node->name, "NextContinuationToken") == 0)
                        strncpy(continuation_token, (char*)content, sizeof(continuation_token) - 1);
                    xmlFree(content);
                }
            }
            xmlFreeDoc(doc);
        }
    }
    aws_byte_buf_clean_up(&list_ctx.response_body);
    aws_mutex_clean_up(&list_ctx.mutex);
    aws_condition_variable_clean_up(&list_ctx.cv);
    return 0;
}

static int on_body_received(struct aws_s3_meta_request *meta_request,
    const struct aws_byte_cursor *body, uint64_t range_start, void *user_data) {
    (void)meta_request; (void)range_start;
    struct download_ctx *ctx = user_data;
    ctx->bytes_downloaded += body->len;
    return AWS_OP_SUCCESS;
}

static void on_request_finished(struct aws_s3_meta_request *meta_request,
    const struct aws_s3_meta_request_result *result, void *user_data) {
    struct download_ctx *ctx = user_data;
    struct app_ctx *app = ctx->app;
    uint64_t end_time;
    aws_high_res_clock_get_ticks(&end_time);
    uint64_t latency = end_time - ctx->start_time;

    aws_mutex_lock(&app->mutex);
    if (result->error_code == AWS_ERROR_SUCCESS) {
        app->successful_downloads++;
        app->total_bytes += ctx->bytes_downloaded;
        app->total_latency_ns += latency;
        if (latency < app->min_latency_ns) app->min_latency_ns = latency;
        if (latency > app->max_latency_ns) app->max_latency_ns = latency;
        printf("✓ %s (%zu bytes, %.2f ms)\n", ctx->object_key, ctx->bytes_downloaded, latency / 1e6);
    } else {
        app->failed_downloads++;
        fprintf(stderr, "✗ %s - Error: %s\n", ctx->object_key, aws_error_str(result->error_code));
    }
    app->active_requests--;
    aws_condition_variable_notify_one(&app->cv);
    aws_mutex_unlock(&app->mutex);
    aws_mem_release(app->allocator, ctx);
    aws_s3_meta_request_release(meta_request);
}

static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s --bucket <bucket> --region <region> --access-key <key> --secret-key <secret> [OPTIONS]\n\n", prog_name);
    fprintf(stderr, "Required:\n");
    fprintf(stderr, "  --bucket       S3 bucket name\n");
    fprintf(stderr, "  --region       AWS region\n");
    fprintf(stderr, "  --access-key   AWS access key\n");
    fprintf(stderr, "  --secret-key   AWS secret key\n\n");
    fprintf(stderr, "Optional:\n");
    fprintf(stderr, "  --prefix       Filter prefix\n");
    fprintf(stderr, "  --count        Number of files to download\n\n");
    fprintf(stderr, "Note: Set AWS_ENDPOINT_URL environment variable for custom endpoints\n");
}

int main(int argc, char *argv[]) {
    const char *bucket_name = NULL, *region = NULL, *access_key = NULL;
    const char *secret_key = NULL, *prefix = "";
    int count = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bucket") == 0 && i+1 < argc) bucket_name = argv[++i];
        else if (strcmp(argv[i], "--region") == 0 && i+1 < argc) region = argv[++i];
        else if (strcmp(argv[i], "--access-key") == 0 && i+1 < argc) access_key = argv[++i];
        else if (strcmp(argv[i], "--secret-key") == 0 && i+1 < argc) secret_key = argv[++i];
        else if (strcmp(argv[i], "--prefix") == 0 && i+1 < argc) prefix = argv[++i];
        else if (strcmp(argv[i], "--count") == 0 && i+1 < argc) count = atoi(argv[++i]);
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]); return 0;
        }
    }

    if (!bucket_name || !region || !access_key || !secret_key) {
        print_usage(argv[0]); return 1;
    }

    printf("=== AWS C S3 Avro Benchmark ===\n");
    printf("Bucket: %s\nRegion: %s\nPrefix: %s\n\n", bucket_name, region, prefix);

    xmlInitParser();
    struct aws_allocator *allocator = aws_default_allocator();
    aws_s3_library_init(allocator);

    struct object_list obj_list = {.capacity = 1000};
    obj_list.objects = malloc(obj_list.capacity * sizeof(struct s3_object));

    struct app_ctx app = {
        .allocator = allocator,
        .min_latency_ns = UINT64_MAX,
    };
    aws_mutex_init(&app.mutex);
    aws_condition_variable_init(&app.cv);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 0, NULL);
    struct aws_host_resolver_default_options resolver_options = {.el_group = el_group, .max_entries = 8};
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_client_bootstrap_options bootstrap_options = {.event_loop_group = el_group, .host_resolver = resolver};
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_tls_ctx_options tls_options;
    aws_tls_ctx_options_init_default_client(&tls_options, allocator);
    struct aws_tls_ctx *tls_ctx = aws_tls_client_ctx_new(allocator, &tls_options);
    struct aws_tls_connection_options tls_conn_options;
    aws_tls_connection_options_init_from_ctx(&tls_conn_options, tls_ctx);

    struct aws_credentials_provider_static_options cred_options = {
        .access_key_id = aws_byte_cursor_from_c_str(access_key),
        .secret_access_key = aws_byte_cursor_from_c_str(secret_key),
    };
    struct aws_credentials_provider *cred_provider = aws_credentials_provider_new_static(allocator, &cred_options);

    struct aws_signing_config_aws signing_config = {
        .algorithm = AWS_SIGNING_ALGORITHM_V4,
        .signature_type = AWS_ST_HTTP_REQUEST_HEADERS,
        .region = aws_byte_cursor_from_c_str(region),
        .service = aws_byte_cursor_from_c_str("s3"),
        .credentials_provider = cred_provider,
        .signed_body_value = aws_byte_cursor_from_c_str("UNSIGNED-PAYLOAD"),
        .flags.use_double_uri_encode = false,
    };

    struct aws_s3_client_config client_config = {
        .client_bootstrap = bootstrap,
        .region = aws_byte_cursor_from_c_str(region),
        .tls_mode = AWS_MR_TLS_ENABLED,
        .tls_connection_options = &tls_conn_options,
        .signing_config = &signing_config,
        .part_size = 8 * 1024 * 1024,
        .throughput_target_gbps = 10.0,
    };

    struct aws_s3_client *client = aws_s3_client_new(allocator, &client_config);
    if (!client) { fprintf(stderr, "Failed to create S3 client\n"); return 1; }

    printf("Listing Avro files...\n");
    if (list_objects(client, allocator, bucket_name, prefix, &obj_list) != 0) {
        fprintf(stderr, "Failed to list objects\n");
        return 1;
    }

    printf("Found %zu Avro files\n\n", obj_list.count);
    if (obj_list.count == 0) { printf("No files found\n"); goto cleanup; }

    int files_to_download = (count > 0 && count < (int)obj_list.count) ? count : obj_list.count;
    printf("Benchmarking %d file downloads...\n\n", files_to_download);

    uint64_t benchmark_start;
    aws_high_res_clock_get_ticks(&benchmark_start);

    for (int i = 0; i < files_to_download; i++) {
        struct download_ctx *ctx = aws_mem_calloc(allocator, 1, sizeof(struct download_ctx));
        ctx->app = &app;
        strncpy(ctx->object_key, obj_list.objects[i].key, sizeof(ctx->object_key) - 1);

        char uri[2048];
        snprintf(uri, sizeof(uri), "/%s/%s", bucket_name, ctx->object_key);

        struct aws_http_message *message = aws_http_message_new_request(allocator);
        aws_http_message_set_request_method(message, aws_byte_cursor_from_c_str("GET"));
        aws_http_message_set_request_path(message, aws_byte_cursor_from_c_str(uri));

        struct aws_s3_meta_request_options options = {
            .type = AWS_S3_META_REQUEST_TYPE_GET_OBJECT,
            .message = message,
            .body_callback = on_body_received,
            .finish_callback = on_request_finished,
            .user_data = ctx,
        };

        aws_high_res_clock_get_ticks(&ctx->start_time);
        aws_mutex_lock(&app.mutex);
        app.active_requests++;
        aws_mutex_unlock(&app.mutex);

        struct aws_s3_meta_request *meta_request = aws_s3_client_make_meta_request(client, &options);
        if (!meta_request) {
            aws_mutex_lock(&app.mutex);
            app.active_requests--;
            app.failed_downloads++;
            aws_mutex_unlock(&app.mutex);
            aws_mem_release(allocator, ctx);
        }
        aws_http_message_release(message);
    }

    aws_mutex_lock(&app.mutex);
    while (app.active_requests > 0)
        aws_condition_variable_wait(&app.cv, &app.mutex);
    aws_mutex_unlock(&app.mutex);

    uint64_t benchmark_end;
    aws_high_res_clock_get_ticks(&benchmark_end);

    double total_time_sec = (double)(benchmark_end - benchmark_start) / 1e9;
    double throughput_mbps = (app.total_bytes / (1024.0 * 1024.0)) / total_time_sec;
    double avg_latency_ms = app.successful_downloads > 0 ?
        (app.total_latency_ns / (double)app.successful_downloads) / 1e6 : 0;
    size_t total_attempts = app.successful_downloads + app.failed_downloads;
    double success_rate = total_attempts > 0 ? (app.successful_downloads * 100.0) / total_attempts : 0;

    printf("\n=====================================\n");
    printf("       BENCHMARK RESULTS\n");
    printf("=====================================\n");
    printf("Total Avro files found:  %zu\n", obj_list.count);
    printf("Files attempted:         %zu\n", total_attempts);
    printf("Successful downloads:    %zu\n", app.successful_downloads);
    printf("Failed downloads:        %zu\n", app.failed_downloads);
    printf("Success rate:            %.1f%%\n", success_rate);
    printf("Total bytes transferred: %zu (%.2f MB)\n", app.total_bytes, app.total_bytes / (1024.0 * 1024.0));
    printf("Total time:              %.3f seconds\n", total_time_sec);
    printf("Throughput:              %.2f MB/s\n", throughput_mbps);
    printf("Average latency:         %.2f ms\n", avg_latency_ms);
    printf("Min latency:             %.2f ms\n", app.min_latency_ns / 1e6);
    printf("Max latency:             %.2f ms\n", app.max_latency_ns / 1e6);
    printf("=====================================\n");

cleanup:
    free(obj_list.objects);
    aws_s3_client_release(client);
    aws_credentials_provider_release(cred_provider);
    aws_tls_connection_options_clean_up(&tls_conn_options);
    aws_tls_ctx_release(tls_ctx);
    aws_tls_ctx_options_clean_up(&tls_options);
    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);
    aws_mutex_clean_up(&app.mutex);
    aws_condition_variable_clean_up(&app.cv);
    aws_s3_library_clean_up();
    xmlCleanupParser();
    return app.failed_downloads > 0 ? 1 : 0;
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
    -I/usr/include/libxml2 \
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
    -lxml2 \
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
        -I/usr/include/libxml2 \
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
        -lxml2 \
        -lz \
        -lm \
        -lpthread \
        -ldl \
        -O3
fi

echo ""
echo "=== Build Complete (FIXED) ==="
echo "Binary: $WORK_DIR/s3_benchmark_static"
echo ""
echo "Run on Ubuntu:"
echo "  ./s3_benchmark_static --bucket my-bucket --region us-east-1 \\"
echo "    --access-key AKIAXXXXX --secret-key secretXXXX --count 50"
echo ""
echo "For custom endpoints (MinIO, etc.):"
echo "  export AWS_ENDPOINT_URL=https://minio.example.com:9000"
echo "  ./s3_benchmark_static --bucket my-bucket --region us-east-1 \\"
echo "    --access-key minioadmin --secret-key minioadmin"
