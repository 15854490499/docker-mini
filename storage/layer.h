#ifndef __LAYER_H__
#define __LAYER_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "driver.h"
#include "utils.h"
#include "io_wrapper.h"
#include "storage_layer.h"
#include "storage_mount_point.h"

#ifdef __cplusplus
extern "C" {
#endif

struct layer {
    char *id;
    char *parent;
    char *mount_point;
    int mount_count;
    char *compressed_digest;
    int64_t compress_size;
    char *uncompressed_digest;
    int64_t uncompress_size;
    bool writable;
};

struct layer_list {
    struct layer **layers;
    size_t layers_len;
};

typedef struct _layer_t_ {
	char *layer_json_path;
	storage_layer *slayer;
	char *mount_point_json_path;
	storage_mount_point *smount_point;
	int hold_refs_num;
	uint64_t refcnt;
} layer_t;

struct layer_store_mount_opts {
    char *mount_label;
    json_map_string_string *mount_opts;
};

struct layer_opts {
    char *parent;
    char **names;
    size_t names_len;
    bool writable;

    char *uncompressed_digest;
    char *compressed_digest;

    // mount options
    struct layer_store_mount_opts *opts;
};

int layer_store_create(const char *id, const struct layer_opts *opts, const struct io_read_wrapper *content, char **new_id);
int layer_store_delete(const char *id);
char *layer_store_mount(const char *id);
int layer_store_umount(const char *id, bool force);
struct layer *layer_store_lookup(const char *name);
layer_t *create_empty_layer();
layer_t *load_layer(const char *fname, const char *mountpoint_fname);
int layer_store_init();
void free_layer_t(layer_t *ptr);
void free_layer(struct layer *l);
//int save_layer(layer_t *layer);
//int save_mount_point(layer_t *layer);
#ifdef __cplusplus
}
#endif

#endif
