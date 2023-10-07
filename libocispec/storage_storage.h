// Generated from storage.json. Do not edit!
#ifndef STORAGE_STORAGE_SCHEMA_H
#define STORAGE_STORAGE_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *id;

    char *digest;

    char **names;
    size_t names_len;

    char *layer;

    char **mapped_layers;
    size_t mapped_layers_len;

    char *metadata;

    char **big_data_names;
    size_t big_data_names_len;

    json_map_string_int64 *big_data_sizes;

    json_map_string_string *big_data_digests;

    char *created;

    char *loaded;

    uint64_t size;

    yajl_val _residual;

    unsigned int size_present : 1;
}
storage_storage;

void free_storage_storage (storage_storage *ptr);

storage_storage *make_storage_storage (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_storage_storage (yajl_gen g, const storage_storage *ptr, const struct parser_context *ctx, parser_error *err);

storage_storage *storage_storage_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

storage_storage *storage_storage_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

storage_storage *storage_storage_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *storage_storage_generate_json(const storage_storage *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

