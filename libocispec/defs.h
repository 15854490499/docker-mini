// Generated from defs.json. Do not edit!
#ifndef DEFS_SCHEMA_H
#define DEFS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "network_port_binding.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char unuseful; // unuseful definition to avoid empty struct
}
defs_map_string_object_element;

void free_defs_map_string_object_element (defs_map_string_object_element *ptr);

defs_map_string_object_element *make_defs_map_string_object_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_map_string_object_element (yajl_gen g, const defs_map_string_object_element *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **keys;
    defs_map_string_object_element **values;
    size_t len;
}
defs_map_string_object;

void free_defs_map_string_object (defs_map_string_object *ptr);

defs_map_string_object *make_defs_map_string_object (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_map_string_object (yajl_gen g, const defs_map_string_object *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *auth;

    yajl_val _residual;
}
defs_map_string_object_auths_element;

void free_defs_map_string_object_auths_element (defs_map_string_object_auths_element *ptr);

defs_map_string_object_auths_element *make_defs_map_string_object_auths_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_map_string_object_auths_element (yajl_gen g, const defs_map_string_object_auths_element *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **keys;
    defs_map_string_object_auths_element **values;
    size_t len;
}
defs_map_string_object_auths;

void free_defs_map_string_object_auths (defs_map_string_object_auths *ptr);

defs_map_string_object_auths *make_defs_map_string_object_auths (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_map_string_object_auths (yajl_gen g, const defs_map_string_object_auths *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    network_port_binding *element;

    yajl_val _residual;
}
defs_map_string_object_port_bindings_element;

void free_defs_map_string_object_port_bindings_element (defs_map_string_object_port_bindings_element *ptr);

defs_map_string_object_port_bindings_element *make_defs_map_string_object_port_bindings_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_map_string_object_port_bindings_element (yajl_gen g, const defs_map_string_object_port_bindings_element *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **keys;
    defs_map_string_object_port_bindings_element **values;
    size_t len;
}
defs_map_string_object_port_bindings;

void free_defs_map_string_object_port_bindings (defs_map_string_object_port_bindings *ptr);

defs_map_string_object_port_bindings *make_defs_map_string_object_port_bindings (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_map_string_object_port_bindings (yajl_gen g, const defs_map_string_object_port_bindings *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **links;
    size_t links_len;

    char **alias;
    size_t alias_len;

    char *network_id;

    char *endpoint_id;

    char *gateway;

    char *ip_address;

    int ip_prefix_len;

    char *i_pv6gateway;

    char *global_i_pv6address;

    int global_i_pv6prefix_len;

    char *mac_address;

    char *if_name;

    json_map_string_string *driver_opts;

    yajl_val _residual;

    unsigned int ip_prefix_len_present : 1;
    unsigned int global_i_pv6prefix_len_present : 1;
}
defs_map_string_object_networks_element;

void free_defs_map_string_object_networks_element (defs_map_string_object_networks_element *ptr);

defs_map_string_object_networks_element *make_defs_map_string_object_networks_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_map_string_object_networks_element (yajl_gen g, const defs_map_string_object_networks_element *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **keys;
    defs_map_string_object_networks_element **values;
    size_t len;
}
defs_map_string_object_networks;

void free_defs_map_string_object_networks (defs_map_string_object_networks *ptr);

defs_map_string_object_networks *make_defs_map_string_object_networks (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_map_string_object_networks (yajl_gen g, const defs_map_string_object_networks *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **test;
    size_t test_len;

    int64_t interval;

    int64_t timeout;

    int64_t start_period;

    int retries;

    bool exit_on_unhealthy;

    yajl_val _residual;

    unsigned int interval_present : 1;
    unsigned int timeout_present : 1;
    unsigned int start_period_present : 1;
    unsigned int retries_present : 1;
    unsigned int exit_on_unhealthy_present : 1;
}
defs_health_check;

void free_defs_health_check (defs_health_check *ptr);

defs_health_check *make_defs_health_check (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_health_check (yajl_gen g, const defs_health_check *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *start;
    char *end;
    int exit_code;
    char *output;
    unsigned int exit_code_present : 1;
}
defs_health_log_element;

void free_defs_health_log_element (defs_health_log_element *ptr);

defs_health_log_element *make_defs_health_log_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *status;

    int failing_streak;

    defs_health_log_element **log;
    size_t log_len;

    yajl_val _residual;

    unsigned int failing_streak_present : 1;
}
defs_health;

void free_defs_health (defs_health *ptr);

defs_health *make_defs_health (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_defs_health (yajl_gen g, const defs_health *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

