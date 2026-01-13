

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
#include <aws/io/uri.h>
#include <aws/s3/s3_client.h>
#include <inttypes.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================= DATA STRUCTS ========================= */

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

    int has_endpoint_override;
    struct aws_uri endpoint_uri;
    char endpoint_authority[512];
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

/* ========================= HELPERS ========================= */

static void set_common_headers(struct aws_http_message *msg,
                               const char *host,
                               const char *accept) {

    aws_http_message_add_header(msg,
        (struct aws_http_header){
            aws_byte_cursor_from_c_str("Host"),
            aws_byte_cursor_from_c_str(host)
        });

    aws_http_message_add_header(msg,
        (struct aws_http_header){
            aws_byte_cursor_from_c_str("User-Agent"),
            aws_byte_cursor_from_c_str("ceph-s3-benchmark/1.0")
        });

    if (accept) {
        aws_http_message_add_header(msg,
            (struct aws_http_header){
                aws_byte_cursor_from_c_str("Accept"),
                aws_byte_cursor_from_c_str(accept)
            });
    }
}

static void build_list_path(char *out, size_t sz,
                            const char *bucket,
                            const char *prefix,
                            const char *token) {

    if (token && token[0]) {
        snprintf(out, sz,
            "/%s/?list-type=2&prefix=%s&continuation-token=%s",
            bucket, prefix, token);
    } else {
        snprintf(out, sz,
            "/%s/?list-type=2&prefix=%s",
            bucket, prefix);
    }
}

static void build_get_path(char *out, size_t sz,
                           const char *bucket,
                           const char *key) {
    snprintf(out, sz, "/%s/%s", bucket, key);
}

/* ========================= ENDPOINT ========================= */

static int parse_endpoint_override(struct app_ctx *app) {
    const char *env = getenv("AWS_ENDPOINT_URL");

    printf("[INFO] AWS_ENDPOINT_URL = %s\n", env ? env : "(not set)");

    if (!env || !env[0]) {
        app->has_endpoint_override = 0;
        return 0;
    }

    struct aws_byte_cursor cur = aws_byte_cursor_from_c_str(env);
    if (aws_uri_init_parse(&app->endpoint_uri, app->allocator, &cur)) {
        fprintf(stderr, "[ERROR] Invalid endpoint URL\n");
        return -1;
    }

    const struct aws_byte_cursor *auth = aws_uri_authority(&app->endpoint_uri);
    memcpy(app->endpoint_authority, auth->ptr, auth->len);
    app->endpoint_authority[auth->len] = '\0';

    printf("[INFO] Using Ceph endpoint: %s\n", app->endpoint_authority);

    app->has_endpoint_override = 1;
    return 0;
}

/* ========================= LIST CALLBACKS ========================= */

static int on_list_body(struct aws_s3_meta_request *req,
                        const struct aws_byte_cursor *body,
                        uint64_t range,
                        void *user) {
    (void)req; (void)range;
    struct list_ctx *ctx = user;
    aws_byte_buf_append_dynamic(&ctx->response_body, body);
    return AWS_OP_SUCCESS;
}

static void on_list_finished(struct aws_s3_meta_request *req,
    const struct aws_s3_meta_request_result *res,
    void *user) {

    struct list_ctx *ctx = user;

    printf("[LIST] HTTP %d | %s\n",
           res->response_status,
           aws_error_str(res->error_code));

    if (res->error_response_body.len) {
        fwrite(res->error_response_body.buffer, 1,
               res->error_response_body.len, stdout);
        printf("\n");
    }

    aws_mutex_lock(&ctx->mutex);
    ctx->done = 1;
    ctx->error = res->error_code != AWS_ERROR_SUCCESS;
    aws_condition_variable_notify_all(&ctx->cv);
    aws_mutex_unlock(&ctx->mutex);

    aws_s3_meta_request_release(req);
}

/* ========================= XML PARSER ========================= */

static void parse_list_objects_xml(const char *xml,
                                   size_t len,
                                   struct object_list *list,
                                   const char *prefix) {

    xmlDoc *doc = xmlReadMemory(xml, len, NULL, NULL, XML_PARSE_RECOVER);
    if (!doc) return;

    xmlNode *root = xmlDocGetRootElement(doc);

    for (xmlNode *n = root->children; n; n = n->next) {
        if (n->type == XML_ELEMENT_NODE &&
            strcmp((char *)n->name, "Contents") == 0) {

            char key[1024] = {0};
            size_t size = 0;

            for (xmlNode *c = n->children; c; c = c->next) {
                if (c->type != XML_ELEMENT_NODE) continue;

                xmlChar *val = xmlNodeGetContent(c);

                if (!strcmp((char *)c->name, "Key"))
                    strncpy(key, (char *)val, sizeof(key) - 1);
                else if (!strcmp((char *)c->name, "Size"))
                    size = strtoull((char *)val, NULL, 10);

                xmlFree(val);
            }

            if (strstr(key, ".avro") || strstr(key, ".AVRO")) {
                if (list->count == list->capacity) {
                    list->capacity *= 2;
                    list->objects = realloc(list->objects,
                        list->capacity * sizeof(struct s3_object));
                }

                strcpy(list->objects[list->count].key, key);
                list->objects[list->count].size = size;
                list->count++;
            }
        }
    }

    xmlFreeDoc(doc);
}

/* ========================= GET CALLBACKS ========================= */

static int on_body_received(struct aws_s3_meta_request *req,
    const struct aws_byte_cursor *body,
    uint64_t range,
    void *user) {
    (void)req; (void)range;
    ((struct download_ctx *)user)->bytes_downloaded += body->len;
    return AWS_OP_SUCCESS;
}

static void on_request_finished(struct aws_s3_meta_request *req,
    const struct aws_s3_meta_request_result *res,
    void *user) {

    struct download_ctx *ctx = user;
    struct app_ctx *app = ctx->app;

    uint64_t end;
    aws_high_res_clock_get_ticks(&end);
    uint64_t latency = end - ctx->start_time;

    aws_mutex_lock(&app->mutex);

    if (res->error_code == AWS_ERROR_SUCCESS) {
        app->successful_downloads++;
        app->total_bytes += ctx->bytes_downloaded;
        app->total_latency_ns += latency;
        if (latency < app->min_latency_ns) app->min_latency_ns = latency;
        if (latency > app->max_latency_ns) app->max_latency_ns = latency;

        printf("✓ %s (%zu bytes)\n",
               ctx->object_key, ctx->bytes_downloaded);
    } else {
        app->failed_downloads++;
        printf("✗ %s (%s)\n",
               ctx->object_key, aws_error_str(res->error_code));
    }

    app->active_requests--;
    aws_condition_variable_notify_one(&app->cv);
    aws_mutex_unlock(&app->mutex);

    aws_mem_release(app->allocator, ctx);
    aws_s3_meta_request_release(req);
}

/* ========================= MAIN ========================= */

int main(int argc, char **argv) {

    const char *bucket = NULL, *region = "us-east-1";
    const char *ak = NULL, *sk = NULL;
    const char *prefix = "";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--bucket")) bucket = argv[++i];
        else if (!strcmp(argv[i], "--access-key")) ak = argv[++i];
        else if (!strcmp(argv[i], "--secret-key")) sk = argv[++i];
        else if (!strcmp(argv[i], "--prefix")) prefix = argv[++i];
    }

    if (!bucket || !ak || !sk) {
        printf("Missing args\n");
        return 1;
    }

    xmlInitParser();
    struct aws_allocator *alloc = aws_default_allocator();
    aws_s3_library_init(alloc);

    struct app_ctx app = {.allocator = alloc, .min_latency_ns = UINT64_MAX};
    aws_mutex_init(&app.mutex);
    aws_condition_variable_init(&app.cv);
    parse_endpoint_override(&app);

    struct aws_event_loop_group *el =
        aws_event_loop_group_new_default(alloc, 0, NULL);

    struct aws_host_resolver *resolver =
        aws_host_resolver_new_default(alloc,
            &(struct aws_host_resolver_default_options){
                .el_group = el, .max_entries = 8 });

    struct aws_client_bootstrap *bootstrap =
        aws_client_bootstrap_new(alloc,
            &(struct aws_client_bootstrap_options){
                .event_loop_group = el,
                .host_resolver = resolver });

    struct aws_credentials_provider *creds =
        aws_credentials_provider_new_static(
            alloc,
            &(struct aws_credentials_provider_static_options){
                aws_byte_cursor_from_c_str(ak),
                aws_byte_cursor_from_c_str(sk) });

    struct aws_signing_config_aws sign = {
        .algorithm = AWS_SIGNING_ALGORITHM_V4,
        .signature_type = AWS_ST_HTTP_REQUEST_HEADERS,
        .region = aws_byte_cursor_from_c_str(region),
        .service = aws_byte_cursor_from_c_str("s3"),
        .credentials_provider = creds,
        .signed_body_value = aws_byte_cursor_from_c_str("UNSIGNED-PAYLOAD"),
    };

    struct aws_s3_client *client =
        aws_s3_client_new(alloc,
            &(struct aws_s3_client_config){
                .client_bootstrap = bootstrap,
                .region = aws_byte_cursor_from_c_str(region),
                .signing_config = &sign,
                .tls_mode = AWS_MR_TLS_DISABLED, /* HTTP Ceph */
                .part_size = 5 * 1024 * 1024,
                .throughput_target_gbps = 1.0,
            });

    printf("\n[READY] Ceph S3 benchmark initialized\n");
    return 0;
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
echo "Run on Ubuntu (AWS S3, virtual-hosted style used automatically):"
echo "  ./s3_benchmark_static --bucket my-bucket --region us-east-1 \\"
echo "    --access-key AKIAXXXXX --secret-key secretXXXX --count 50"
echo ""
echo "For custom endpoints (MinIO, etc.):"
echo "  export AWS_ENDPOINT_URL=https://minio.example.com:9000"
echo "  ./s3_benchmark_static --bucket my-bucket --region us-east-1 \\"
echo "    --access-key minioadmin --secret-key minioadmin"
