// Generated from rootfs.json. Do not edit!
#ifndef STORAGE_ROOTFS_SCHEMA_H
#define STORAGE_ROOTFS_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int container_id;
    int host_id;
    int size;
    unsigned int container_id_present : 1;
    unsigned int host_id_present : 1;
    unsigned int size_present : 1;
}
storage_rootfs_uidmap_element;

void free_storage_rootfs_uidmap_element (storage_rootfs_uidmap_element *ptr);

storage_rootfs_uidmap_element *make_storage_rootfs_uidmap_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int container_id;
    int host_id;
    int size;
    unsigned int container_id_present : 1;
    unsigned int host_id_present : 1;
    unsigned int size_present : 1;
}
storage_rootfs_gidmap_element;

void free_storage_rootfs_gidmap_element (storage_rootfs_gidmap_element *ptr);

storage_rootfs_gidmap_element *make_storage_rootfs_gidmap_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *id;

    char **names;
    size_t names_len;

    char *image;

    char *layer;

    char *metadata;

    char *created;

    storage_rootfs_uidmap_element **uidmap;
    size_t uidmap_len;

    storage_rootfs_gidmap_element **gidmap;
    size_t gidmap_len;

    yajl_val _residual;
}
storage_rootfs;

void free_storage_rootfs (storage_rootfs *ptr);

storage_rootfs *make_storage_rootfs (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_storage_rootfs (yajl_gen g, const storage_rootfs *ptr, const struct parser_context *ctx, parser_error *err);

storage_rootfs *storage_rootfs_parse_file(const char *filename, const struct parser_context *ctx, parser_error *err);

storage_rootfs *storage_rootfs_parse_file_stream(FILE *stream, const struct parser_context *ctx, parser_error *err);

storage_rootfs *storage_rootfs_parse_data(const char *jsondata, const struct parser_context *ctx, parser_error *err);

char *storage_rootfs_generate_json(const storage_rootfs *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

