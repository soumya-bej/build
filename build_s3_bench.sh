#!/bin/bash
set -e

AWS C S3 Benchmark Builder and Runner - LOOP VERSION
- Builds aws-c-* libraries
- Builds a benchmark tool that optionally uploads one sample object
and then repeatedly GETs the same object in a loop.
WORK_DIR="$HOME/aws-s3-benchmark"
BUILD_DIR="$WORK_DIR/build"
INSTALL_DIR="$WORK_DIR/install"
SRC_DIR="$WORK_DIR/src"

echo "=== AWS C S3 Benchmark Setup (Loop Version) ==="
echo "Working directory: $WORK_DIR"

Create directories
mkdir -p "$BUILD_DIR" "$INSTALL_DIR" "$SRC_DIR"

Install dependencies (Fedora)
echo "Installing dependencies..."
sudo dnf install -y
gcc
gcc-c++
cmake
git
openssl-devel
libcurl-devel
zlib-devel
glibc-static
libstdc++-static
libxml2-devel
libxml2-static
perl

cd "$SRC_DIR"

Clone dependencies in correct order
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
name="${repo%%:}"
url="${repo#:}"
if [ ! -d "$name" ]; then
git clone --depth 1 "$url" "$name"
fi
done

Function to build a library
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

Build all libraries in order
for repo in "${repos[@]}"; do
name="${repo%%:*}"
build_library "$name"
done

Create the loop-based benchmark C program
echo "Creating loop benchmark program source..."
cat > "$WORK_DIR/s3_benchmark.c" << 'EOFCODE'
#include <aws/common/allocator.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/logging.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>

#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>

#include <aws/auth/credentials.h>
#include <aws/auth/signing_config.h>

#include <aws/http/request_response.h>
#include <aws/io/stream.h>
#include <aws/s3/s3_client.h>
#include <aws/s3/s3_client_config.h>
#include <aws/s3/s3_meta_request.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ===================== Context structs ===================== */

struct app_ctx {
struct aws_allocator *allocator;
struct aws_mutex mutex;
struct aws_condition_variable cv;
int request_finished;
int request_success;
uint64_t bytes_transferred;
uint64_t start_ns;
uint64_t end_ns;
};

struct req_ctx {
struct app_ctx *app;
};

/* ===================== Callbacks ===================== */

static int s_body_callback(
struct aws_s3_meta_request *meta_request,
const struct aws_byte_cursor *body,
uint64_t range_start,
void *user_data) {

(void)meta_request;
(void)range_start;

struct req_ctx *ctx = user_data;
struct app_ctx *app = ctx->app;

aws_mutex_lock(&app->mutex);
app->bytes_transferred += body->len;
aws_mutex_unlock(&app->mutex);

return AWS_OP_SUCCESS;
}

static void s_finished_callback(
struct aws_s3_meta_request *meta_request,
const struct aws_s3_meta_request_result *result,
void *user_data) {

(void)meta_request;

struct req_ctx *ctx = user_data;
struct app_ctx *app = ctx->app;

aws_mutex_lock(&app->mutex);

aws_high_res_clock_get_ticks(&app->end_ns);
app->request_finished = 1;
app->request_success = (result->error_code == AWS_ERROR_SUCCESS);

fprintf(stderr,
        "[FINISH] HTTP %d, error: %s (%d)\n",
        result->response_status,
        aws_error_str(result->error_code),
        result->error_code);

if (result->error_response_body.len) {
    fprintf(stderr, "[ERROR BODY]\n%.*s\n",
            (int)result->error_response_body.len,
            (const char *)result->error_response_body.buffer);
}

aws_condition_variable_notify_all(&app->cv);
aws_mutex_unlock(&app->mutex);
}

/* ===================== CLI parsing ===================== */

struct cli_options {
const char *bucket;
const char *key;
const char *region;
const char *access_key;
const char *secret_key;
int count;
int upload_first;
};

static int parse_cli(int argc, char **argv, struct cli_options *out) {
memset(out, 0, sizeof(*out));
out->region = "us-east-1";
out->count = 10;

for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--bucket") && i + 1 < argc) {
        out->bucket = argv[++i];
    } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
        out->key = argv[++i];
    } else if (!strcmp(argv[i], "--region") && i + 1 < argc) {
        out->region = argv[++i];
    } else if (!strcmp(argv[i], "--access-key") && i + 1 < argc) {
        out->access_key = argv[++i];
    } else if (!strcmp(argv[i], "--secret-key") && i + 1 < argc) {
        out->secret_key = argv[++i];
    } else if (!strcmp(argv[i], "--count") && i + 1 < argc) {
        out->count = atoi(argv[++i]);
    } else if (!strcmp(argv[i], "--upload")) {
        out->upload_first = 1;
    } else if (!strcmp(argv[i], "--help")) {
        return -1;
    }
}

if (!out->bucket || !out->key || !out->access_key || !out->secret_key) {
    return -1;
}

if (out->count <= 0) {
    out->count = 1;
}

return 0;
}

static void print_usage(const char *prog) {
fprintf(stderr,
"Usage: %s --bucket --key "
"--region --access-key --secret-key "
"[--count N] [--upload]\n"
"Environment:\n"
" AWS_ENDPOINT_URL=http://host:port (Ceph/MinIO endpoint)\n",
prog);
}

/* ===================== Helpers to build messages ===================== */

static struct aws_http_message *build_get_request(
struct aws_allocator *allocator,
const char *bucket,
const char *key,
const char *endpoint_env) {

char path_buf[2048];
snprintf(path_buf, sizeof(path_buf), "/%s/%s", bucket, key);

struct aws_http_message *msg =
    aws_http_message_new_request(allocator);
aws_http_message_set_request_method(
    msg,
    aws_byte_cursor_from_c_str("GET"));
aws_http_message_set_request_path(
    msg,
    aws_byte_cursor_from_c_str(path_buf));

if (endpoint_env && endpoint_env[0]) {
    const char *host_start = strstr(endpoint_env, "://");
    const char *host = host_start ? host_start + 3 : endpoint_env;
    aws_http_message_add_header(
        msg,
        (struct aws_http_header){
            .name = aws_byte_cursor_from_c_str("Host"),
            .value = aws_byte_cursor_from_c_str(host),
        });
}

aws_http_message_add_header(
    msg,
    (struct aws_http_header){
        .name = aws_byte_cursor_from_c_str("User-Agent"),
        .value = aws_byte_cursor_from_c_str("aws-c-s3-benchmark/loop"),
    });

return msg;
}

static struct aws_http_message *build_put_request(
struct aws_allocator *allocator,
const char *bucket,
const char *key,
const char *endpoint_env,
struct aws_byte_cursor body_cursor) {

char path_buf[2048];
snprintf(path_buf, sizeof(path_buf), "/%s/%s", bucket, key);

struct aws_http_message *msg =
    aws_http_message_new_request(allocator);
aws_http_message_set_request_method(
    msg,
    aws_byte_cursor_from_c_str("PUT"));
aws_http_message_set_request_path(
    msg,
    aws_byte_cursor_from_c_str(path_buf));

if (endpoint_env && endpoint_env[0]) {
    const char *host_start = strstr(endpoint_env, "://");
    const char *host = host_start ? host_start + 3 : endpoint_env;
    aws_http_message_add_header(
        msg,
        (struct aws_http_header){
            .name = aws_byte_cursor_from_c_str("Host"),
            .value = aws_byte_cursor_from_c_str(host),
        });
}

aws_http_message_add_header(
    msg,
    (struct aws_http_header){
        .name = aws_byte_cursor_from_c_str("User-Agent"),
        .value = aws_byte_cursor_from_c_str("aws-c-s3-benchmark/loop"),
    });

char len_buf[64];
snprintf(len_buf, sizeof(len_buf), "%" PRIu64, (uint64_t)body_cursor.len);

aws_http_message_add_header(
    msg,
    (struct aws_http_header){
        .name = aws_byte_cursor_from_c_str("Content-Length"),
        .value = aws_byte_cursor_from_c_str(len_buf),
    });

struct aws_input_stream *body_stream =
    aws_input_stream_new_from_cursor(allocator, &body_cursor);
aws_http_message_set_body_stream(msg, body_stream);

return msg;
}

/* ===================== Run one meta request (GET/PUT) ===================== */

static int run_meta_request(
struct aws_s3_client *s3_client,
enum aws_s3_meta_request_type type,
struct aws_http_message *msg,
struct app_ctx *app) {

app->request_finished = 0;
app->request_success = 0;
app->bytes_transferred = 0;
aws_high_res_clock_get_ticks(&app->start_ns);

struct req_ctx rctx;
rctx.app = app;

struct aws_s3_meta_request_options mr_opts;
AWS_ZERO_STRUCT(mr_opts);
mr_opts.type = type;
mr_opts.message = msg;
mr_opts.user_data = &rctx;
mr_opts.on_body = s_body_callback;
mr_opts.on_finish = s_finished_callback;

struct aws_s3_meta_request *meta_request =
    aws_s3_client_make_meta_request(s3_client, &mr_opts);

if (!meta_request) {
    fprintf(stderr, "[ERROR] Failed to create meta request: %s\n",
            aws_error_str(aws_last_error()));
    return -1;
}

aws_mutex_lock(&app->mutex);
while (!app->request_finished) {
    aws_condition_variable_wait(&app->cv, &app->mutex);
}
aws_mutex_unlock(&app->mutex);

aws_s3_meta_request_release(meta_request);

return app->request_success ? 0 : -1;
}

/* ===================== Main ===================== */

int main(int argc, char **argv) {
struct cli_options opt;
if (parse_cli(argc, argv, &opt)) {
print_usage(argv[0]);
return 1;
}

const char *endpoint_env = getenv("AWS_ENDPOINT_URL");
if (endpoint_env && endpoint_env[0]) {
    fprintf(stderr, "[INFO] Using endpoint override: %s\n", endpoint_env);
} else {
    fprintf(stderr,
            "[WARN] AWS_ENDPOINT_URL not set; using default S3 endpoints.\n");
}

struct aws_allocator *allocator = aws_default_allocator();
aws_common_library_init(allocator);
aws_auth_library_init(allocator);
aws_http_library_init(allocator);
aws_s3_library_init(allocator);

struct aws_event_loop_group *el_group =
    aws_event_loop_group_new_default(allocator, 0, NULL);

struct aws_host_resolver *host_resolver =
    aws_host_resolver_new_default(
        allocator,
        &(struct aws_host_resolver_default_options){
            .el_group = el_group,
            .max_entries = 8,
        });

struct aws_client_bootstrap *bootstrap =
    aws_client_bootstrap_new(
        allocator,
        &(struct aws_client_bootstrap_options){
            .event_loop_group = el_group,
            .host_resolver = host_resolver,
        });

struct aws_credentials_provider *provider =
    aws_credentials_provider_new_static(
        allocator,
        &(struct aws_credentials_provider_static_options){
            .access_key_id = aws_byte_cursor_from_c_str(opt.access_key),
            .secret_access_key = aws_byte_cursor_from_c_str(opt.secret_key),
            .session_token = aws_byte_cursor_from_c_str(""),
        });

struct aws_signing_config_aws signing_config;
AWS_ZERO_STRUCT(signing_config);
signing_config.config_type = AWS_SIGNING_CONFIG_AWS;
signing_config.algorithm = AWS_SIGNING_ALGORITHM_V4;
signing_config.signature_type = AWS_ST_HTTP_REQUEST_HEADERS;
signing_config.region = aws_byte_cursor_from_c_str(opt.region);
signing_config.service = aws_byte_cursor_from_c_str("s3");
signing_config.credentials_provider = provider;
signing_config.signed_body_value = aws_byte_cursor_from_c_str("UNSIGNED-PAYLOAD");
signing_config.use_double_uri_encode = true;
signing_config.should_normalize_uri_path = true;

struct aws_s3_client_config client_cfg;
AWS_ZERO_STRUCT(client_cfg);
client_cfg.client_bootstrap = bootstrap;
client_cfg.region = aws_byte_cursor_from_c_str(opt.region);
client_cfg.signing_config = &signing_config;
client_cfg.part_size = 8 * 1024 * 1024;
client_cfg.throughput_target_gbps = 10.0;
client_cfg.tls_mode = AWS_MR_TLS_DISABLED; /* HTTP Ceph */

if (endpoint_env && endpoint_env[0]) {
    client_cfg.endpoint_override = aws_byte_cursor_from_c_str(endpoint_env);
}

struct aws_s3_client *s3_client = aws_s3_client_new(allocator, &client_cfg);
if (!s3_client) {
    fprintf(stderr, "[ERROR] Failed to create S3 client: %s\n",
            aws_error_str(aws_last_error()));
    goto cleanup;
}

fprintf(stderr,
        "[INFO] S3 client ready. Bucket=%s, Key=%s, Region=%s, Count=%d\n",
        opt.bucket, opt.key, opt.region, opt.count);

struct app_ctx app;
AWS_ZERO_STRUCT(app);
app.allocator = allocator;
aws_mutex_init(&app.mutex);
aws_condition_variable_init(&app.cv);

/* Optional: upload a small sample object first */
if (opt.upload_first) {
    const char *sample = "This is a small test payload for S3 benchmark.\n";
    struct aws_byte_cursor body_cursor =
        aws_byte_cursor_from_c_str(sample);

    fprintf(stderr, "[UPLOAD] Uploading sample object to %s/%s\n",
            opt.bucket, opt.key);

    struct aws_http_message *put_msg =
        build_put_request(allocator, opt.bucket, opt.key,
                          endpoint_env, body_cursor);

    if (run_meta_request(
            s3_client, AWS_S3_META_REQUEST_TYPE_PUT_OBJECT,
            put_msg, &app) != 0) {

        fprintf(stderr, "[UPLOAD] Failed, cannot proceed with benchmark.\n");
        struct aws_input_stream *body_stream =
            aws_http_message_get_body_stream(put_msg);
        if (body_stream) {
            aws_input_stream_release(body_stream);
        }
        aws_http_message_release(put_msg);
        goto cleanup_client;
    }

    fprintf(stderr,
            "[UPLOAD] Success, uploaded %" PRIu64 " bytes.\n",
            app.bytes_transferred);

    struct aws_input_stream *body_stream =
        aws_http_message_get_body_stream(put_msg);
    if (body_stream) {
        aws_input_stream_release(body_stream);
    }
    aws_http_message_release(put_msg);
}

/* Benchmark loop: GET same key N times */
uint64_t total_bytes = 0;
uint64_t total_ns = 0;
int success_count = 0;

for (int i = 0; i < opt.count; ++i) {
    fprintf(stderr, "\n[GET %d/%d] Downloading %s/%s\n",
            i + 1, opt.count, opt.bucket, opt.key);

    struct aws_http_message *get_msg =
        build_get_request(allocator, opt.bucket, opt.key, endpoint_env);

    if (run_meta_request(
            s3_client, AWS_S3_META_REQUEST_TYPE_GET_OBJECT,
            get_msg, &app) == 0) {

        uint64_t dt = app.end_ns - app.start_ns;
        double ms = (double)dt / 1.0e6;
        double mb = app.bytes_transferred / (1024.0 * 1024.0);
        double mbps = (ms > 0.0) ? (mb / (ms / 1000.0)) : 0.0;

        fprintf(stderr,
                "[GET %d] OK: bytes=%" PRIu64 ", time=%.2f ms, "
                "throughput=%.2f MB/s\n",
                i + 1, app.bytes_transferred, ms, mbps);

        total_bytes += app.bytes_transferred;
        total_ns += dt;
        success_count++;
    } else {
        fprintf(stderr, "[GET %d] FAILED\n", i + 1);
    }

    aws_http_message_release(get_msg);
}

if (success_count > 0) {
    double total_ms = (double)total_ns / 1.0e6;
    double total_mb = total_bytes / (1024.0 * 1024.0);
    double overall_mbps =
        (total_ms > 0.0) ? (total_mb / (total_ms / 1000.0)) : 0.0;
    double avg_ms = total_ms / success_count;

    fprintf(stderr,
            "\n[SUMMARY] successful=%d/%d, total_bytes=%" PRIu64
            ", total_time=%.2f ms, avg_time=%.2f ms, "
            "overall_throughput=%.2f MB/s\n",
            success_count, opt.count, total_bytes,
            total_ms, avg_ms, overall_mbps);
} else {
    fprintf(stderr, "\n[SUMMARY] All GETs failed.\n");
}
cleanup_client:
if (s3_client) {
aws_s3_client_release(s3_client);
}

cleanup:
if (bootstrap) {
aws_client_bootstrap_release(bootstrap);
}
if (host_resolver) {
aws_host_resolver_release(host_resolver);
}
if (el_group) {
aws_event_loop_group_release(el_group);
}
if (provider) {
aws_credentials_provider_release(provider);
}

aws_s3_library_clean_up();
aws_http_library_clean_up();
aws_auth_library_clean_up();
aws_common_library_clean_up();

return 0;
}
EOFCODE

Show libraries we built
echo "Locating libraries..."
for dir in "$INSTALL_DIR/lib" "$INSTALL_DIR/lib64"; do
if [ -d "$dir" ]; then
echo " $dir:"
ls -la "$dir"/*.a 2>/dev/null || echo " (no .a files)"
fi
done

echo ""
echo "Compiling loop benchmark program..."
gcc -o "$WORK_DIR/s3_benchmark_static" "$WORK_DIR/s3_benchmark.c"
-I"$INSTALL_DIR/include"
-L"$INSTALL_DIR/lib"
-L"$INSTALL_DIR/lib64"
-laws-c-s3
-laws-c-auth
-laws-checksums
-laws-c-http
-laws-c-io
-laws-c-compression
-laws-c-cal
-laws-c-sdkutils
-laws-c-common
-ls2n
-lcrypto
-lssl
-lcurl
-lz
-lm
-lpthread
-ldl
-O3

echo ""
echo "=== Build Complete (Loop Version) ==="
echo "Binary: $WORK_DIR/s3_benchmark_static"
echo ""
echo "Example 1: upload a small sample object, then GET it 20 times:"
echo " export AWS_ENDPOINT_URL=http://10.10.103.12:425"
echo " $WORK_DIR/s3_benchmark_static \"
echo " --bucket prd-aua-notifier-store-181 \"
echo " --key benchmark-test-file.avro \"
echo " --region us-east-1 \"
echo " --access-key <ACCESS_KEY> \"
echo " --secret-key <SECRET_KEY> \"
echo " --count 20 \"
echo " --upload"
echo ""
echo "Example 2: repeatedly GET an existing Avro file (no upload):"
echo " export AWS_ENDPOINT_URL=http://10.10.103.12:425"
echo " $WORK_DIR/s3_benchmark_static \"
echo " --bucket prd-aua-notifier-store-181 \"
echo " --key path/to/existing/file.avro \"
echo " --region us-east-1 \"
echo " --access-key <ACCESS_KEY> \"
echo " --secret-key <SECRET_KEY> \"
echo " --count 50"