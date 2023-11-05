// Generated from defs.json. Do not edit!
#ifndef OCI_RUNTIME_DEFS_SCHEMA_H
#define OCI_RUNTIME_DEFS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *path;

    char **args;
    size_t args_len;

    char **env;
    size_t env_len;

    int timeout;

    yajl_val _residual;

    unsigned int timeout_present : 1;
}
oci_runtime_defs_hook;

void free_oci_runtime_defs_hook (oci_runtime_defs_hook *ptr);

oci_runtime_defs_hook *make_oci_runtime_defs_hook (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_hook (yajl_gen g, const oci_runtime_defs_hook *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    uint32_t container_id;

    uint32_t host_id;

    uint32_t size;

    yajl_val _residual;

    unsigned int container_id_present : 1;
    unsigned int host_id_present : 1;
    unsigned int size_present : 1;
}
oci_runtime_defs_id_mapping;

void free_oci_runtime_defs_id_mapping (oci_runtime_defs_id_mapping *ptr);

oci_runtime_defs_id_mapping *make_oci_runtime_defs_id_mapping (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_id_mapping (yajl_gen g, const oci_runtime_defs_id_mapping *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *source;

    char *destination;

    char **options;
    size_t options_len;

    char *type;

    oci_runtime_defs_id_mapping **uid_mappings;
    size_t uid_mappings_len;

    oci_runtime_defs_id_mapping **gid_mappings;
    size_t gid_mappings_len;

    yajl_val _residual;
}
oci_runtime_defs_mount;

void free_oci_runtime_defs_mount (oci_runtime_defs_mount *ptr);

oci_runtime_defs_mount *make_oci_runtime_defs_mount (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_mount (yajl_gen g, const oci_runtime_defs_mount *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

