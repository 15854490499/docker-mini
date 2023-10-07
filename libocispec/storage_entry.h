// Generated from entry.json. Do not edit!
#ifndef STORAGE_ENTRY_SCHEMA_H
#define STORAGE_ENTRY_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t type;

    char *name;

    uint8_t *name_raw;
    size_t name_raw_len;

    int64_t size;

    char *payload;

    int32_t position;

    yajl_val _residual;

    unsigned int type_present : 1;
    unsigned int size_present : 1;
    unsigned int position_present : 1;
}
storage_entry;

void free_storage_entry (storage_entry *ptr);

storage_entry *make_storage_entry (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_storage_entry (yajl_gen g, const storage_entry *ptr, const struct parser_context *ctx, parser_error *err);

storage_entry *storage_entry_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

storage_entry *storage_entry_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

storage_entry *storage_entry_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *storage_entry_generate_json(const storage_entry *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

