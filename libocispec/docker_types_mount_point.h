// Generated from mount-point.json. Do not edit!
#ifndef DOCKER_TYPES_MOUNT_POINT_SCHEMA_H
#define DOCKER_TYPES_MOUNT_POINT_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *type;

    char *name;

    char *source;

    char *destination;

    char *driver;

    char *mode;

    bool rw;

    char *propagation;

    yajl_val _residual;

    unsigned int rw_present : 1;
}
docker_types_mount_point;

void free_docker_types_mount_point (docker_types_mount_point *ptr);

docker_types_mount_point *make_docker_types_mount_point (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_docker_types_mount_point (yajl_gen g, const docker_types_mount_point *ptr, const struct parser_context *ctx, parser_error *err);

docker_types_mount_point *docker_types_mount_point_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

docker_types_mount_point *docker_types_mount_point_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

docker_types_mount_point *docker_types_mount_point_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *docker_types_mount_point_generate_json(const docker_types_mount_point *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

