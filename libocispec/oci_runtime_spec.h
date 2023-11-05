// Generated from spec.json. Do not edit!
#ifndef OCI_RUNTIME_SPEC_SCHEMA_H
#define OCI_RUNTIME_SPEC_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "oci_runtime_defs.h"
#include "oci_runtime_config_linux.h"
#include "oci_runtime_defs_linux.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *path;

    bool readonly;

    yajl_val _residual;

    unsigned int readonly_present : 1;
}
oci_runtime_spec_root;

void free_oci_runtime_spec_root (oci_runtime_spec_root *ptr);

oci_runtime_spec_root *make_oci_runtime_spec_root (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_spec_root (yajl_gen g, const oci_runtime_spec_root *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *oci_version;

    char *hostname;

    oci_runtime_defs_mount **mounts;
    size_t mounts_len;

    oci_runtime_spec_root *root;

    oci_runtime_config_linux *linux;

    yajl_val _residual;
}
oci_runtime_spec;

void free_oci_runtime_spec (oci_runtime_spec *ptr);

oci_runtime_spec *make_oci_runtime_spec (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_spec (yajl_gen g, const oci_runtime_spec *ptr, const struct parser_context *ctx, parser_error *err);

oci_runtime_spec *oci_runtime_spec_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

oci_runtime_spec *oci_runtime_spec_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

oci_runtime_spec *oci_runtime_spec_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *oci_runtime_spec_generate_json(const oci_runtime_spec *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

