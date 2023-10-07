// Generated from auths.json. Do not edit!
#ifndef IMAGE_SPEC_SCHEMA_AUTHS_SCHEMA_H
#define IMAGE_SPEC_SCHEMA_AUTHS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "image_spec_schema_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    image_spec_schema_defs_map_string_object_auths *auths;

    yajl_val _residual;
}
image_spec_schema_auths;

void free_image_spec_schema_auths (image_spec_schema_auths *ptr);

image_spec_schema_auths *make_image_spec_schema_auths (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_image_spec_schema_auths (yajl_gen g, const image_spec_schema_auths *ptr, const struct parser_context *ctx, parser_error *err);

image_spec_schema_auths *image_spec_schema_auths_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

image_spec_schema_auths *image_spec_schema_auths_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

image_spec_schema_auths *image_spec_schema_auths_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *image_spec_schema_auths_generate_json(const image_spec_schema_auths *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

