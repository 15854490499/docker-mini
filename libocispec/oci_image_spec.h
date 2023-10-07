// Generated from spec.json. Do not edit!
#ifndef OCI_IMAGE_SPEC_SCHEMA_H
#define OCI_IMAGE_SPEC_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *user;

    defs_map_string_object *exposed_ports;

    char **env;
    size_t env_len;

    char **entrypoint;
    size_t entrypoint_len;

    char **cmd;
    size_t cmd_len;

    defs_map_string_object *volumes;

    char *working_dir;

    json_map_string_string *labels;

    char *stop_signal;

    defs_health_check *healthcheck;

    yajl_val _residual;
}
oci_image_spec_config;

void free_oci_image_spec_config (oci_image_spec_config *ptr);

oci_image_spec_config *make_oci_image_spec_config (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_image_spec_config (yajl_gen g, const oci_image_spec_config *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **diff_ids;
    size_t diff_ids_len;

    char *type;

    yajl_val _residual;
}
oci_image_spec_rootfs;

void free_oci_image_spec_rootfs (oci_image_spec_rootfs *ptr);

oci_image_spec_rootfs *make_oci_image_spec_rootfs (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_image_spec_rootfs (yajl_gen g, const oci_image_spec_rootfs *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *created;
    char *author;
    char *created_by;
    char *comment;
    bool empty_layer;
    unsigned int empty_layer_present : 1;
}
oci_image_spec_history_element;

void free_oci_image_spec_history_element (oci_image_spec_history_element *ptr);

oci_image_spec_history_element *make_oci_image_spec_history_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *created;

    char *author;

    char *architecture;

    char *os;

    oci_image_spec_config *config;

    oci_image_spec_rootfs *rootfs;

    oci_image_spec_history_element **history;
    size_t history_len;

    yajl_val _residual;
}
oci_image_spec;

void free_oci_image_spec (oci_image_spec *ptr);

oci_image_spec *make_oci_image_spec (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_image_spec (yajl_gen g, const oci_image_spec *ptr, const struct parser_context *ctx, parser_error *err);

oci_image_spec *oci_image_spec_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

oci_image_spec *oci_image_spec_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

oci_image_spec *oci_image_spec_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *oci_image_spec_generate_json(const oci_image_spec *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

