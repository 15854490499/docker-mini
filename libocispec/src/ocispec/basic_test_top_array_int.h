// Generated from test_top_array_int.json. Do not edit!
#ifndef BASIC_TEST_TOP_ARRAY_INT_SCHEMA_H
#define BASIC_TEST_TOP_ARRAY_INT_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t *items;
    size_t len;

}
basic_test_top_array_int_container;

void free_basic_test_top_array_int_container (basic_test_top_array_int_container *ptr);

basic_test_top_array_int_container *basic_test_top_array_int_container_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

basic_test_top_array_int_container *basic_test_top_array_int_container_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

basic_test_top_array_int_container *basic_test_top_array_int_container_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *basic_test_top_array_int_container_generate_json(const basic_test_top_array_int_container *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

