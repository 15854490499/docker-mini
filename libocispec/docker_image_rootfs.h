// Generated from rootfs.json. Do not edit!
#ifndef DOCKER_IMAGE_ROOTFS_SCHEMA_H
#define DOCKER_IMAGE_ROOTFS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *type;

    char **diff_ids;
    size_t diff_ids_len;

    yajl_val _residual;
}
docker_image_rootfs;

void free_docker_image_rootfs (docker_image_rootfs *ptr);

docker_image_rootfs *make_docker_image_rootfs (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_docker_image_rootfs (yajl_gen g, const docker_image_rootfs *ptr, const struct parser_context *ctx, parser_error *err);

docker_image_rootfs *docker_image_rootfs_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

docker_image_rootfs *docker_image_rootfs_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

docker_image_rootfs *docker_image_rootfs_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *docker_image_rootfs_generate_json(const docker_image_rootfs *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

