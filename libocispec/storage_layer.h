// Generated from layer.json. Do not edit!
#ifndef STORAGE_LAYER_SCHEMA_H
#define STORAGE_LAYER_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *id;

    char **names;
    size_t names_len;

    char *parent;

    char *metadata;

    char *mountlabel;

    char *created;

    char *compressed_diff_digest;

    int64_t compressed_size;

    char *diff_digest;

    int64_t diff_size;

    uint32_t compression;

    bool incomplete;

    bool writable;

    yajl_val _residual;

    unsigned int compressed_size_present : 1;
    unsigned int diff_size_present : 1;
    unsigned int compression_present : 1;
    unsigned int incomplete_present : 1;
    unsigned int writable_present : 1;
}
storage_layer;

void free_storage_layer (storage_layer *ptr);

storage_layer *make_storage_layer (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_storage_layer (yajl_gen g, const storage_layer *ptr, const struct parser_context *ctx, parser_error *err);

storage_layer *storage_layer_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

storage_layer *storage_layer_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

storage_layer *storage_layer_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *storage_layer_generate_json(const storage_layer *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

