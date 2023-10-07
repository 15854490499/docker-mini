// Generated from manifest_schema2.json. Do not edit!
#ifndef REGISTRY_MANIFEST_SCHEMA2_SCHEMA_H
#define REGISTRY_MANIFEST_SCHEMA2_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *media_type;

    int size;

    char *digest;

    yajl_val _residual;

    unsigned int size_present : 1;
}
registry_manifest_schema2_config;

void free_registry_manifest_schema2_config (registry_manifest_schema2_config *ptr);

registry_manifest_schema2_config *make_registry_manifest_schema2_config (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_registry_manifest_schema2_config (yajl_gen g, const registry_manifest_schema2_config *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *media_type;
    int64_t size;
    char *digest;
    unsigned int size_present : 1;
}
registry_manifest_schema2_layers_element;

void free_registry_manifest_schema2_layers_element (registry_manifest_schema2_layers_element *ptr);

registry_manifest_schema2_layers_element *make_registry_manifest_schema2_layers_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int schema_version;

    char *media_type;

    registry_manifest_schema2_config *config;

    registry_manifest_schema2_layers_element **layers;
    size_t layers_len;

    yajl_val _residual;

    unsigned int schema_version_present : 1;
}
registry_manifest_schema2;

void free_registry_manifest_schema2 (registry_manifest_schema2 *ptr);

registry_manifest_schema2 *make_registry_manifest_schema2 (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_registry_manifest_schema2 (yajl_gen g, const registry_manifest_schema2 *ptr, const struct parser_context *ctx, parser_error *err);

registry_manifest_schema2 *registry_manifest_schema2_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

registry_manifest_schema2 *registry_manifest_schema2_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

registry_manifest_schema2 *registry_manifest_schema2_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *registry_manifest_schema2_generate_json(const registry_manifest_schema2 *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

