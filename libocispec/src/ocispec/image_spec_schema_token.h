// Generated from token.json. Do not edit!
#ifndef IMAGE_SPEC_SCHEMA_TOKEN_SCHEMA_H
#define IMAGE_SPEC_SCHEMA_TOKEN_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *token;

    char *access_token;

    uint32_t expires_in;

    char *issued_at;

    char *refresh_token;

    yajl_val _residual;

    unsigned int expires_in_present : 1;
}
image_spec_schema_token;

void free_image_spec_schema_token (image_spec_schema_token *ptr);

image_spec_schema_token *make_image_spec_schema_token (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_image_spec_schema_token (yajl_gen g, const image_spec_schema_token *ptr, const struct parser_context *ctx, parser_error *err);

image_spec_schema_token *image_spec_schema_token_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

image_spec_schema_token *image_spec_schema_token_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

image_spec_schema_token *image_spec_schema_token_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *image_spec_schema_token_generate_json(const image_spec_schema_token *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

