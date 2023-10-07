// Generated from inner_port_mapping.json. Do not edit!
#ifndef CNI_INNER_PORT_MAPPING_SCHEMA_H
#define CNI_INNER_PORT_MAPPING_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t host_port;

    int32_t container_port;

    char *protocol;

    char *host_ip;

    yajl_val _residual;

    unsigned int host_port_present : 1;
    unsigned int container_port_present : 1;
}
cni_inner_port_mapping;

void free_cni_inner_port_mapping (cni_inner_port_mapping *ptr);

cni_inner_port_mapping *make_cni_inner_port_mapping (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_cni_inner_port_mapping (yajl_gen g, const cni_inner_port_mapping *ptr, const struct parser_context *ctx, parser_error *err);

cni_inner_port_mapping *cni_inner_port_mapping_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

cni_inner_port_mapping *cni_inner_port_mapping_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

cni_inner_port_mapping *cni_inner_port_mapping_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *cni_inner_port_mapping_generate_json(const cni_inner_port_mapping *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

