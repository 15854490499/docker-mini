// Generated from defs.json. Do not edit!
#ifndef IMAGE_SPEC_SCHEMA_DEFS_SCHEMA_H
#define IMAGE_SPEC_SCHEMA_DEFS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char unuseful; // unuseful definition to avoid empty struct
}
image_spec_schema_defs_map_string_object_element;

void free_image_spec_schema_defs_map_string_object_element (image_spec_schema_defs_map_string_object_element *ptr);

image_spec_schema_defs_map_string_object_element *make_image_spec_schema_defs_map_string_object_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_image_spec_schema_defs_map_string_object_element (yajl_gen g, const image_spec_schema_defs_map_string_object_element *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **keys;
    image_spec_schema_defs_map_string_object_element **values;
    size_t len;
}
image_spec_schema_defs_map_string_object;

void free_image_spec_schema_defs_map_string_object (image_spec_schema_defs_map_string_object *ptr);

image_spec_schema_defs_map_string_object *make_image_spec_schema_defs_map_string_object (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_image_spec_schema_defs_map_string_object (yajl_gen g, const image_spec_schema_defs_map_string_object *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *auth;

    yajl_val _residual;
}
image_spec_schema_defs_map_string_object_auths_element;

void free_image_spec_schema_defs_map_string_object_auths_element (image_spec_schema_defs_map_string_object_auths_element *ptr);

image_spec_schema_defs_map_string_object_auths_element *make_image_spec_schema_defs_map_string_object_auths_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_image_spec_schema_defs_map_string_object_auths_element (yajl_gen g, const image_spec_schema_defs_map_string_object_auths_element *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **keys;
    image_spec_schema_defs_map_string_object_auths_element **values;
    size_t len;
}
image_spec_schema_defs_map_string_object_auths;

void free_image_spec_schema_defs_map_string_object_auths (image_spec_schema_defs_map_string_object_auths *ptr);

image_spec_schema_defs_map_string_object_auths *make_image_spec_schema_defs_map_string_object_auths (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_image_spec_schema_defs_map_string_object_auths (yajl_gen g, const image_spec_schema_defs_map_string_object_auths *ptr, const struct parser_context *ctx, parser_error *err);

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
image_spec_schema_defs_health_check;

void free_image_spec_schema_defs_health_check (image_spec_schema_defs_health_check *ptr);

image_spec_schema_defs_health_check *make_image_spec_schema_defs_health_check (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_image_spec_schema_defs_health_check (yajl_gen g, const image_spec_schema_defs_health_check *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

