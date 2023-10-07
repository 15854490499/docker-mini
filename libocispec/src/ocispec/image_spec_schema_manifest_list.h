// Generated from manifest_list.json. Do not edit!
#ifndef IMAGE_SPEC_SCHEMA_MANIFEST_LIST_SCHEMA_H
#define IMAGE_SPEC_SCHEMA_MANIFEST_LIST_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "image_spec_schema_defs.h"

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

    char **features;
    size_t features_len;

    yajl_val _residual;
}
image_spec_schema_manifest_list_manifests_platform;

void free_image_spec_schema_manifest_list_manifests_platform (image_spec_schema_manifest_list_manifests_platform *ptr);

image_spec_schema_manifest_list_manifests_platform *make_image_spec_schema_manifest_list_manifests_platform (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_image_spec_schema_manifest_list_manifests_platform (yajl_gen g, const image_spec_schema_manifest_list_manifests_platform *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *media_type;
    int size;
    char *digest;
    image_spec_schema_manifest_list_manifests_platform *platform;
    unsigned int size_present : 1;
}
image_spec_schema_manifest_list_manifests_element;

void free_image_spec_schema_manifest_list_manifests_element (image_spec_schema_manifest_list_manifests_element *ptr);

image_spec_schema_manifest_list_manifests_element *make_image_spec_schema_manifest_list_manifests_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int schema_version;

    char *media_type;

    image_spec_schema_manifest_list_manifests_element **manifests;
    size_t manifests_len;

    yajl_val _residual;

    unsigned int schema_version_present : 1;
}
image_spec_schema_manifest_list;

void free_image_spec_schema_manifest_list (image_spec_schema_manifest_list *ptr);

image_spec_schema_manifest_list *make_image_spec_schema_manifest_list (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_image_spec_schema_manifest_list (yajl_gen g, const image_spec_schema_manifest_list *ptr, const struct parser_context *ctx, parser_error *err);

image_spec_schema_manifest_list *image_spec_schema_manifest_list_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

image_spec_schema_manifest_list *image_spec_schema_manifest_list_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

image_spec_schema_manifest_list *image_spec_schema_manifest_list_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *image_spec_schema_manifest_list_generate_json(const image_spec_schema_manifest_list *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

