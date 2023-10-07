// Generated from token.json. Do not edit!
#ifndef REGISTRY_TOKEN_SCHEMA_H
#define REGISTRY_TOKEN_SCHEMA_H

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
registry_token;

void free_registry_token (registry_token *ptr);

registry_token *make_registry_token (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_registry_token (yajl_gen g, const registry_token *ptr, const struct parser_context *ctx, parser_error *err);

registry_token *registry_token_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

registry_token *registry_token_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

registry_token *registry_token_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *registry_token_generate_json(const registry_token *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

