// Generated from config.json. Do not edit!
#ifndef CONTAINER_CONFIG_SCHEMA_H
#define CONTAINER_CONFIG_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *hostname;

    char *domainname;

    char *user;

    bool attach_stdin;

    bool attach_stdout;

    bool attach_stderr;

    defs_map_string_object *exposed_ports;

    char *publish_service;

    bool tty;

    bool open_stdin;

    bool stdin_once;

    char **env;
    size_t env_len;

    char **cmd;
    size_t cmd_len;

    bool args_escaped;

    char *image;

    char *image_ref;

    defs_map_string_object *volumes;

    char *working_dir;

    char **entrypoint;
    size_t entrypoint_len;

    bool network_disabled;

    char *mac_address;

    char **onbuild;
    size_t onbuild_len;

    json_map_string_string *labels;

    char *log_driver;

    json_map_string_string *annotations;

    char *stop_signal;

    defs_health_check *healthcheck;

    bool system_container;

    char *ns_change_opt;

    char **mounts;
    size_t mounts_len;

    yajl_val _residual;

    unsigned int attach_stdin_present : 1;
    unsigned int attach_stdout_present : 1;
    unsigned int attach_stderr_present : 1;
    unsigned int tty_present : 1;
    unsigned int open_stdin_present : 1;
    unsigned int stdin_once_present : 1;
    unsigned int args_escaped_present : 1;
    unsigned int network_disabled_present : 1;
    unsigned int system_container_present : 1;
}
container_config;

void free_container_config (container_config *ptr);

container_config *make_container_config (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_container_config (yajl_gen g, const container_config *ptr, const struct parser_context *ctx, parser_error *err);

container_config *container_config_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

container_config *container_config_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

container_config *container_config_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *container_config_generate_json(const container_config *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

