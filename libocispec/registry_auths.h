// Generated from auths.json. Do not edit!
#ifndef REGISTRY_AUTHS_SCHEMA_H
#define REGISTRY_AUTHS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    defs_map_string_object_auths *auths;

    yajl_val _residual;
}
registry_auths;

void free_registry_auths (registry_auths *ptr);

registry_auths *make_registry_auths (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_registry_auths (yajl_gen g, const registry_auths *ptr, const struct parser_context *ctx, parser_error *err);

registry_auths *registry_auths_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

registry_auths *registry_auths_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

registry_auths *registry_auths_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *registry_auths_generate_json(const registry_auths *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

