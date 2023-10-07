// Generated from anno_port_mappings.json. Do not edit!
#ifndef CNI_ANNO_PORT_MAPPINGS_SCHEMA_H
#define CNI_ANNO_PORT_MAPPINGS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "cni_inner_port_mapping.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t host_port;
    int32_t container_port;
    char *protocol;
    char *host_ip;
    unsigned int host_port_present : 1;
    unsigned int container_port_present : 1;
}
cni_anno_port_mappings_element;

void free_cni_anno_port_mappings_element (cni_anno_port_mappings_element *ptr);

cni_anno_port_mappings_element *make_cni_anno_port_mappings_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    cni_anno_port_mappings_element **items;
    size_t len;

}
cni_anno_port_mappings_container;

void free_cni_anno_port_mappings_container (cni_anno_port_mappings_container *ptr);

cni_anno_port_mappings_container *cni_anno_port_mappings_container_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

cni_anno_port_mappings_container *cni_anno_port_mappings_container_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

cni_anno_port_mappings_container *cni_anno_port_mappings_container_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *cni_anno_port_mappings_container_generate_json(const cni_anno_port_mappings_container *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

