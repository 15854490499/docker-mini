// Generated from manifest_schema1.json. Do not edit!
#ifndef REGISTRY_MANIFEST_SCHEMA1_SCHEMA_H
#define REGISTRY_MANIFEST_SCHEMA1_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *blob_sum;
}
registry_manifest_schema1_fs_layers_element;

void free_registry_manifest_schema1_fs_layers_element (registry_manifest_schema1_fs_layers_element *ptr);

registry_manifest_schema1_fs_layers_element *make_registry_manifest_schema1_fs_layers_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *v1compatibility;
}
registry_manifest_schema1_history_element;

void free_registry_manifest_schema1_history_element (registry_manifest_schema1_history_element *ptr);

registry_manifest_schema1_history_element *make_registry_manifest_schema1_history_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *name;

    char *tag;

    char *architecture;

    registry_manifest_schema1_fs_layers_element **fs_layers;
    size_t fs_layers_len;

    registry_manifest_schema1_history_element **history;
    size_t history_len;

    int schema_version;

    yajl_val _residual;

    unsigned int schema_version_present : 1;
}
registry_manifest_schema1;

void free_registry_manifest_schema1 (registry_manifest_schema1 *ptr);

registry_manifest_schema1 *make_registry_manifest_schema1 (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_registry_manifest_schema1 (yajl_gen g, const registry_manifest_schema1 *ptr, const struct parser_context *ctx, parser_error *err);

registry_manifest_schema1 *registry_manifest_schema1_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

registry_manifest_schema1 *registry_manifest_schema1_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

registry_manifest_schema1 *registry_manifest_schema1_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *registry_manifest_schema1_generate_json(const registry_manifest_schema1 *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

