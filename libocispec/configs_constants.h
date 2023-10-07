// Generated from constants.json. Do not edit!
#ifndef CONFIGS_CONSTANTS_SCHEMA_H
#define CONFIGS_CONSTANTS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *default_host;

    json_map_string_string *registry_transformation;

    yajl_val _residual;
}
configs_constants;

void free_configs_constants (configs_constants *ptr);

configs_constants *make_configs_constants (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_configs_constants (yajl_gen g, const configs_constants *ptr, const struct parser_context *ctx, parser_error *err);

configs_constants *configs_constants_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

configs_constants *configs_constants_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

configs_constants *configs_constants_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *configs_constants_generate_json(const configs_constants *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

