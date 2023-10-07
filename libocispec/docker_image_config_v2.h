// Generated from config-v2.json. Do not edit!
#ifndef DOCKER_IMAGE_CONFIG_V2_SCHEMA_H
#define DOCKER_IMAGE_CONFIG_V2_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "container_config.h"
#include "defs.h"
#include "docker_image_rootfs.h"
#include "docker_image_history.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *id;

    char *parent;

    char *comment;

    char *created;

    char *container;

    char *docker_version;

    char *author;

    container_config *config;
    
	container_config *container_config;

    char *architecture;

    char *os;

    int64_t size;

    char *from;

    docker_image_rootfs *rootfs;

    docker_image_history **history;
    size_t history_len;

    uint8_t *raw_json;
    size_t raw_json_len;

    char *computed_id;

    yajl_val _residual;

    unsigned int size_present : 1;
}
docker_image_config_v2;

void free_docker_image_config_v2 (docker_image_config_v2 *ptr);

docker_image_config_v2 *make_docker_image_config_v2 (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_docker_image_config_v2 (yajl_gen g, const docker_image_config_v2 *ptr, const struct parser_context *ctx, parser_error *err);

docker_image_config_v2 *docker_image_config_v2_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

docker_image_config_v2 *docker_image_config_v2_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

docker_image_config_v2 *docker_image_config_v2_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *docker_image_config_v2_generate_json(const docker_image_config_v2 *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

