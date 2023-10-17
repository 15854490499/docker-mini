#ifndef __STORAGE_H__
#define __STORAGE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "storage_storage.h"
#include "storage_spec.h"
#include "storage_rootfs.h"
#include "timestamp.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define storage_dir "/var/lib/docker-mini/overlay-images"
#define IMAGE_DIGEST_BIG_DATA_KEY "manifest"
#define IMAGE_NAME_LEN 64
#define IMAGE_JSON "images.json"

#define DIGEST_PREFIX "@sha256:"
#define MAX_IMAGE_DIGEST_LENGTH 64

typedef struct {
	char *id;

	char **repo_tags;
	size_t repo_tags_len;

	char **repo_digests;
	size_t repo_digests_len;

	char *top_layer;

	uint64_t size;
	
	char *created;
	
	char *loaded;
	
	char *username;
} image_summary;


typedef struct _image_t_ {
	storage_storage* simage;
	storage_spec* spec;
	uint64_t refcnt;
} image_t;

struct storage_img_create_options {
	types_timestamp_t* create_time;
	char* digest;
};

typedef struct storage_layer_create_opts {
	const char *parent;
	const char *uncompress_digest;
    const char *compressed_digest;
    const char *layer_data_path;
    bool writable;
    json_map_string_string *storage_opts;
} storage_layer_create_opts_t;

struct id_map {
    int container_id;
    int host_id;
    int size;
};

struct id_mapping_options {
    bool host_uid_mapping;
    bool host_gid_mapping;

    struct id_map *uid_map;
    size_t uid_map_len;
    struct id_map *gid_map;
    size_t gid_map_len;
};

struct storage_rootfs_options {
    struct id_mapping_options id_mapping_opts;
    char **label_opts;
    size_t label_opts_len;
    char **mount_opts;
    size_t mount_opts_len;
};

int storage_layer_create(const char *layer_id, storage_layer_create_opts_t *copts);
int storage_layer_delete(const char *layer_id);
int storage_rootfs_create(const char *container_id, const char *image, const char *mount_label, json_map_string_string *storage_opts, char **mountpoint);
int storage_rootfs_delete(const char *container_id);
char *storage_rootfs_mount(const char *container_id);
int storage_rootfs_umount(const char *container_id, bool force);
char *image_store_top_layer(const char *id);
char *image_store_big_data(const char *id, const char *key);
int storage_img_set_image_size(const char *image_id);
int storage_img_set_names(const char *img_id, const char **names, size_t names_len);
int storage_img_get_names(const char *image_name, char ***names, size_t *names_len);
bool storage_image_exist(const char *name);
char *storage_img_get_image_id(const char *image_name);
int image_store_add_name(const char *id, const char *name);
int storage_img_delete(const char *img_id, bool commit);
int storage_img_create(const char* id, const char* parent_id, const char* metadata, struct storage_img_create_options *opts);
int storage_img_set_big_data(const char* img_id, const char* key, const char* val);
int storage_img_set_loaded_time(const char *img_id, types_timestamp_t *loaded_time);
int image_store_init();
char *get_container_mount_point(const char *image_name);
int umount_point(const char *container_id);
image_summary *storage_img_get_summary(const char *img_id);
void free_image_summary(image_summary *summary);
#ifdef __cplusplus
}
#endif

#endif
