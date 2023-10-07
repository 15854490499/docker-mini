// Generated from config-zos.json. Do not edit!
#ifndef RUNTIME_SPEC_SCHEMA_CONFIG_ZOS_SCHEMA_H
#define RUNTIME_SPEC_SCHEMA_CONFIG_ZOS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "runtime_spec_schema_defs_zos.h"
#include "runtime_spec_schema_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    runtime_spec_schema_defs_zos_device **devices;
    size_t devices_len;

    yajl_val _residual;
}
runtime_spec_schema_config_zos;

void free_runtime_spec_schema_config_zos (runtime_spec_schema_config_zos *ptr);

runtime_spec_schema_config_zos *make_runtime_spec_schema_config_zos (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_runtime_spec_schema_config_zos (yajl_gen g, const runtime_spec_schema_config_zos *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

