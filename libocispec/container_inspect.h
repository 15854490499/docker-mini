// Generated from inspect.json. Do not edit!
#ifndef CONTAINER_INSPECT_SCHEMA_H
#define CONTAINER_INSPECT_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"
#include "docker_types_mount_point.h"
#include "container_network_settings.h"
#include "network_port_binding.h"
#include "cni_anno_port_mappings.h"
#include "cni_inner_port_mapping.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *status;

    bool running;

    bool paused;

    bool restarting;

    int pid;

    int exit_code;

    char *error;

    char *started_at;

    char *finished_at;

    defs_health *health;

    yajl_val _residual;

    unsigned int running_present : 1;
    unsigned int paused_present : 1;
    unsigned int restarting_present : 1;
    unsigned int pid_present : 1;
    unsigned int exit_code_present : 1;
}
container_inspect_state;

void free_container_inspect_state (container_inspect_state *ptr);

container_inspect_state *make_container_inspect_state (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_container_inspect_state (yajl_gen g, const container_inspect_state *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *page_size;
    uint64_t limit;
    unsigned int limit_present : 1;
}
container_inspect_resources_hugetlbs_element;

void free_container_inspect_resources_hugetlbs_element (container_inspect_resources_hugetlbs_element *ptr);

container_inspect_resources_hugetlbs_element *make_container_inspect_resources_hugetlbs_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int64_t cpu_period;

    int64_t cpu_quota;

    int64_t cpu_shares;

    int64_t memory;

    int64_t memory_swap;

    container_inspect_resources_hugetlbs_element **hugetlbs;
    size_t hugetlbs_len;

    json_map_string_string *unified;

    yajl_val _residual;

    unsigned int cpu_period_present : 1;
    unsigned int cpu_quota_present : 1;
    unsigned int cpu_shares_present : 1;
    unsigned int memory_present : 1;
    unsigned int memory_swap_present : 1;
}
container_inspect_resources;

void free_container_inspect_resources (container_inspect_resources *ptr);

container_inspect_resources *make_container_inspect_resources (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_container_inspect_resources (yajl_gen g, const container_inspect_resources *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *lower_dir;

    char *merged_dir;

    char *upper_dir;

    char *work_dir;

    char *device_id;

    char *device_name;

    char *device_size;

    yajl_val _residual;
}
container_inspect_graph_driver_data;

void free_container_inspect_graph_driver_data (container_inspect_graph_driver_data *ptr);

container_inspect_graph_driver_data *make_container_inspect_graph_driver_data (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_container_inspect_graph_driver_data (yajl_gen g, const container_inspect_graph_driver_data *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    container_inspect_graph_driver_data *data;

    char *name;

    yajl_val _residual;
}
container_inspect_graph_driver;

void free_container_inspect_graph_driver (container_inspect_graph_driver *ptr);

container_inspect_graph_driver *make_container_inspect_graph_driver (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_container_inspect_graph_driver (yajl_gen g, const container_inspect_graph_driver *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *hostname;

    char *user;

    char **env;
    size_t env_len;

    bool tty;

    char **cmd;
    size_t cmd_len;

    char **entrypoint;
    size_t entrypoint_len;

    json_map_string_string *labels;

    defs_map_string_object *volumes;

    json_map_string_string *annotations;

    defs_health_check *health_check;

    char *image;

    char *image_ref;

    char *stop_signal;

    yajl_val _residual;

    unsigned int tty_present : 1;
}
container_inspect_config;

void free_container_inspect_config (container_inspect_config *ptr);

container_inspect_config *make_container_inspect_config (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_container_inspect_config (yajl_gen g, const container_inspect_config *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *id;

    char *created;

    char *path;

    char **args;
    size_t args_len;

    container_inspect_state *state;

    container_inspect_resources *resources;

    char *image;

    char *resolv_conf_path;

    char *hostname_path;

    char *hosts_path;

    char *log_path;

    char *name;

    int restart_count;

    char *mount_label;

    char *process_label;

    char *seccomp_profile;

    bool no_new_privileges;

    container_inspect_graph_driver *graph_driver;

    docker_types_mount_point **mounts;
    size_t mounts_len;

    container_inspect_config *config;

    container_network_settings *network_settings;

    yajl_val _residual;

    unsigned int restart_count_present : 1;
    unsigned int no_new_privileges_present : 1;
}
container_inspect;

void free_container_inspect (container_inspect *ptr);

container_inspect *make_container_inspect (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_container_inspect (yajl_gen g, const container_inspect *ptr, const struct parser_context *ctx, parser_error *err);

container_inspect *container_inspect_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

container_inspect *container_inspect_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

container_inspect *container_inspect_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *container_inspect_generate_json(const container_inspect *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

