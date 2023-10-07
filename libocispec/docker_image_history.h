// Generated from history.json. Do not edit!
#ifndef DOCKER_IMAGE_HISTORY_SCHEMA_H
#define DOCKER_IMAGE_HISTORY_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *created;

    char *author;

    char *created_by;

    char *comment;

    bool empty_layer;

    yajl_val _residual;

    unsigned int empty_layer_present : 1;
}
docker_image_history;

void free_docker_image_history (docker_image_history *ptr);

docker_image_history *make_docker_image_history (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_docker_image_history (yajl_gen g, const docker_image_history *ptr, const struct parser_context *ctx, parser_error *err);

docker_image_history *docker_image_history_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

docker_image_history *docker_image_history_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

docker_image_history *docker_image_history_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *docker_image_history_generate_json(const docker_image_history *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

