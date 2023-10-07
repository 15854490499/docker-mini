// Generated from manifest_list.json. Do not edit!
#ifndef REGISTRY_MANIFEST_LIST_SCHEMA_H
#define REGISTRY_MANIFEST_LIST_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *architecture;

    char *os;

    char *os_version;

    char **os_features;
    size_t os_features_len;

    char *variant;

    char **features;
    size_t features_len;

    yajl_val _residual;
}
registry_manifest_list_manifests_platform;

void free_registry_manifest_list_manifests_platform (registry_manifest_list_manifests_platform *ptr);

registry_manifest_list_manifests_platform *make_registry_manifest_list_manifests_platform (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_registry_manifest_list_manifests_platform (yajl_gen g, const registry_manifest_list_manifests_platform *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *media_type;
    int size;
    char *digest;
    registry_manifest_list_manifests_platform *platform;
    unsigned int size_present : 1;
}
registry_manifest_list_manifests_element;

void free_registry_manifest_list_manifests_element (registry_manifest_list_manifests_element *ptr);

registry_manifest_list_manifests_element *make_registry_manifest_list_manifests_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int schema_version;

    char *media_type;

    registry_manifest_list_manifests_element **manifests;
    size_t manifests_len;

    yajl_val _residual;

    unsigned int schema_version_present : 1;
}
registry_manifest_list;

void free_registry_manifest_list (registry_manifest_list *ptr);

registry_manifest_list *make_registry_manifest_list (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_registry_manifest_list (yajl_gen g, const registry_manifest_list *ptr, const struct parser_context *ctx, parser_error *err);

registry_manifest_list *registry_manifest_list_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

registry_manifest_list *registry_manifest_list_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

registry_manifest_list *registry_manifest_list_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *registry_manifest_list_generate_json(const registry_manifest_list *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

