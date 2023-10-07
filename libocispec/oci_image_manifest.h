// Generated from manifest.json. Do not edit!
#ifndef OCI_IMAGE_MANIFEST_SCHEMA_H
#define OCI_IMAGE_MANIFEST_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "oci_image_content_descriptor.h"
#include "oci_image_defs_descriptor.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int schema_version;

    oci_image_content_descriptor *config;

    oci_image_content_descriptor **layers;
    size_t layers_len;

    json_map_string_string *annotations;

    yajl_val _residual;

    unsigned int schema_version_present : 1;
}
oci_image_manifest;

void free_oci_image_manifest (oci_image_manifest *ptr);

oci_image_manifest *make_oci_image_manifest (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_image_manifest (yajl_gen g, const oci_image_manifest *ptr, const struct parser_context *ctx, parser_error *err);

oci_image_manifest *oci_image_manifest_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

oci_image_manifest *oci_image_manifest_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

oci_image_manifest *oci_image_manifest_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *oci_image_manifest_generate_json(const oci_image_manifest *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

