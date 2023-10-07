// Generated from defs-zos.json. Do not edit!
#ifndef RUNTIME_SPEC_SCHEMA_DEFS_ZOS_SCHEMA_H
#define RUNTIME_SPEC_SCHEMA_DEFS_ZOS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "runtime_spec_schema_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *path;

    char *type;

    int64_t major;

    int64_t minor;

    int file_mode;

    uid_t uid;

    gid_t gid;

    yajl_val _residual;

    unsigned int major_present : 1;
    unsigned int minor_present : 1;
    unsigned int file_mode_present : 1;
    unsigned int uid_present : 1;
    unsigned int gid_present : 1;
}
runtime_spec_schema_defs_zos_device;

void free_runtime_spec_schema_defs_zos_device (runtime_spec_schema_defs_zos_device *ptr);

runtime_spec_schema_defs_zos_device *make_runtime_spec_schema_defs_zos_device (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_runtime_spec_schema_defs_zos_device (yajl_gen g, const runtime_spec_schema_defs_zos_device *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

