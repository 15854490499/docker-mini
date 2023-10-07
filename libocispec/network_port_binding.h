// Generated from port_binding.json. Do not edit!
#ifndef NETWORK_PORT_BINDING_SCHEMA_H
#define NETWORK_PORT_BINDING_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *host_ip;
    char *host_port;
}
network_port_binding_host_element;

void free_network_port_binding_host_element (network_port_binding_host_element *ptr);

network_port_binding_host_element *make_network_port_binding_host_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    network_port_binding_host_element **host;
    size_t host_len;

    yajl_val _residual;
}
network_port_binding;

void free_network_port_binding (network_port_binding *ptr);

network_port_binding *make_network_port_binding (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_network_port_binding (yajl_gen g, const network_port_binding *ptr, const struct parser_context *ctx, parser_error *err);

network_port_binding *network_port_binding_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

network_port_binding *network_port_binding_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

network_port_binding *network_port_binding_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *network_port_binding_generate_json(const network_port_binding *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

