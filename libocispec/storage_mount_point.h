// Generated from mount-point.json. Do not edit!
#ifndef STORAGE_MOUNT_POINT_SCHEMA_H
#define STORAGE_MOUNT_POINT_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *id;

    int32_t count;

    char *path;

    yajl_val _residual;

    unsigned int count_present : 1;
}
storage_mount_point;

void free_storage_mount_point (storage_mount_point *ptr);

storage_mount_point *make_storage_mount_point (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_storage_mount_point (yajl_gen g, const storage_mount_point *ptr, const struct parser_context *ctx, parser_error *err);

storage_mount_point *storage_mount_point_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

storage_mount_point *storage_mount_point_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

storage_mount_point *storage_mount_point_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *storage_mount_point_generate_json(const storage_mount_point *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

