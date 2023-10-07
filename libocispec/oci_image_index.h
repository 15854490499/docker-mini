// Generated from index.json. Do not edit!
#ifndef OCI_IMAGE_INDEX_SCHEMA_H
#define OCI_IMAGE_INDEX_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "oci_image_defs_descriptor.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *architecture;

    char *os;

    char *os_version;

    char **os_features;
    size_t os_features_len;

    char *variant;

    yajl_val _residual;
}
oci_image_index_manifests_platform;

void free_oci_image_index_manifests_platform (oci_image_index_manifests_platform *ptr);

oci_image_index_manifests_platform *make_oci_image_index_manifests_platform (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_image_index_manifests_platform (yajl_gen g, const oci_image_index_manifests_platform *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *media_type;
    int64_t size;
    char *digest;
    char **urls;
    size_t urls_len;

    oci_image_index_manifests_platform *platform;
    json_map_string_string *annotations;
    unsigned int size_present : 1;
}
oci_image_index_manifests_element;

void free_oci_image_index_manifests_element (oci_image_index_manifests_element *ptr);

oci_image_index_manifests_element *make_oci_image_index_manifests_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int schema_version;

    oci_image_index_manifests_element **manifests;
    size_t manifests_len;

    json_map_string_string *annotations;

    yajl_val _residual;

    unsigned int schema_version_present : 1;
}
oci_image_index;

void free_oci_image_index (oci_image_index *ptr);

oci_image_index *make_oci_image_index (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_image_index (yajl_gen g, const oci_image_index *ptr, const struct parser_context *ctx, parser_error *err);

oci_image_index *oci_image_index_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

oci_image_index *oci_image_index_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

oci_image_index *oci_image_index_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *oci_image_index_generate_json(const oci_image_index *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

