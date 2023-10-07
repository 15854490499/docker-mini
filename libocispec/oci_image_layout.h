// Generated from layout.json. Do not edit!
#ifndef OCI_IMAGE_LAYOUT_SCHEMA_H
#define OCI_IMAGE_LAYOUT_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *image_layout_version;

    yajl_val _residual;
}
oci_image_layout;

void free_oci_image_layout (oci_image_layout *ptr);

oci_image_layout *make_oci_image_layout (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_image_layout (yajl_gen g, const oci_image_layout *ptr, const struct parser_context *ctx, parser_error *err);

oci_image_layout *oci_image_layout_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

oci_image_layout *oci_image_layout_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

oci_image_layout *oci_image_layout_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *oci_image_layout_generate_json(const oci_image_layout *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

