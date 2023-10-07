// Generated from network-settings.json. Do not edit!
#ifndef CONTAINER_NETWORK_SETTINGS_SCHEMA_H
#define CONTAINER_NETWORK_SETTINGS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"
#include "network_port_binding.h"
#include "cni_anno_port_mappings.h"
#include "cni_inner_port_mapping.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *bridge;

    char *sandbox_id;

    char *link_local_i_pv6address;

    int link_local_i_pv6prefix_len;

    defs_map_string_object_port_bindings *ports;

    cni_inner_port_mapping **cni_ports;
    size_t cni_ports_len;

    char *sandbox_key;

    char *endpoint_id;

    char *gateway;

    char *global_i_pv6address;

    int global_i_pv6prefix_len;

    char *ip_address;

    int ip_prefix_len;

    char *i_pv6gateway;

    char *mac_address;

    bool activation;

    defs_map_string_object_networks *networks;

    yajl_val _residual;

    unsigned int link_local_i_pv6prefix_len_present : 1;
    unsigned int global_i_pv6prefix_len_present : 1;
    unsigned int ip_prefix_len_present : 1;
    unsigned int activation_present : 1;
}
container_network_settings;

void free_container_network_settings (container_network_settings *ptr);

container_network_settings *make_container_network_settings (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_container_network_settings (yajl_gen g, const container_network_settings *ptr, const struct parser_context *ctx, parser_error *err);

container_network_settings *container_network_settings_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

container_network_settings *container_network_settings_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

container_network_settings *container_network_settings_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *container_network_settings_generate_json(const container_network_settings *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

