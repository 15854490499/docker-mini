// Generated from content-descriptor.json. Do not edit!
#ifndef OCI_IMAGE_CONTENT_DESCRIPTOR_SCHEMA_H
#define OCI_IMAGE_CONTENT_DESCRIPTOR_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "oci_image_defs_descriptor.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *media_type;

    int64_t size;

    char *digest;

    char **urls;
    size_t urls_len;

    json_map_string_string *annotations;

    yajl_val _residual;

    unsigned int size_present : 1;
}
oci_image_content_descriptor;

void free_oci_image_content_descriptor (oci_image_content_descriptor *ptr);

oci_image_content_descriptor *make_oci_image_content_descriptor (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_image_content_descriptor (yajl_gen g, const oci_image_content_descriptor *ptr, const struct parser_context *ctx, parser_error *err);

oci_image_content_descriptor *oci_image_content_descriptor_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

oci_image_content_descriptor *oci_image_content_descriptor_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

oci_image_content_descriptor *oci_image_content_descriptor_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *oci_image_content_descriptor_generate_json(const oci_image_content_descriptor *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

