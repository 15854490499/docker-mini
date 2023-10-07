#ifndef __DRIVER_H__
#define __DRIVER_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "project_quota.h"
#include "io_wrapper.h"
#include "container_inspect.h"

#ifdef __cplusplus
extern "C" {
#endif

#define driver_home "/var/lib/docker-mini/overlay"
#define MAX_LAYER_ID_LENGTH 26
struct driver_create_opts {
	char *mount_label;
	json_map_string_string *storage_opt;
};

struct overlay_options {
	bool override_kernelcheck;
	uint64_t default_quota;
	const char *mount_program;
	bool skip_mount_home;
	const char *mount_options;
};

struct driver_mount_opts {
    char *mount_label;
    char **options;
    size_t options_len;
};

struct graphdriver;

struct graphdriver_ops {
    int (*init)(struct graphdriver *driver, const char *drvier_home, const char **options, size_t len);

    int (*create_rw)(const char *id, const char *parent, const struct graphdriver *driver,
                     struct driver_create_opts *create_opts);

    int (*create_ro)(const char *id, const char *parent, const struct graphdriver *driver,
                     const struct driver_create_opts *create_opts);

    int (*rm_layer)(const char *id, const struct graphdriver *driver);

    char *(*mount_layer)(const char *id, const struct graphdriver *driver, const struct driver_mount_opts *mount_opts);

    int (*umount_layer)(const char *id, const struct graphdriver *driver);

    //bool (*exists)(const char *id, const struct graphdriver *driver);

    int (*apply_diff)(const char *id, const struct graphdriver *driver, const struct io_read_wrapper *content);

    int (*get_layer_metadata)(const char *id, const struct graphdriver *driver, json_map_string_string *map_info);

    //int (*get_driver_status)(const struct graphdriver *driver, struct graphdriver_status *status);

    //int (*clean_up)(struct graphdriver *driver);

    //int (*try_repair_lowers)(const char *id, const char *parent, const struct graphdriver *driver);

    //int (*get_layer_fs_info)(const char *id, const struct graphdriver *driver, imagetool_fs_info *fs_info);
};

struct graphdriver {
    // common implement
    const struct graphdriver_ops *ops;
    const char *name;
    const char *home;
    char *backing_fs;
    bool support_dtype;

    bool support_quota;

    struct pquota_control *quota_ctrl;

    // options for overlay2
    struct overlay_options *overlay_opts;

    // options for device mapper
    //struct device_set *devset;
};

int graphdriver_init();
int graphdriver_create_rw(const char *id, const char *parent, struct driver_create_opts *create_opts);
int graphdriver_create_ro(const char *id, const char *parent, const struct driver_create_opts *create_opts);
struct pquota_control *project_quota_control_init(const char *home_dir, const char *fs);
int overlay2_get_layer_metadata(const char *id, const struct graphdriver *driver, json_map_string_string *map_info);
char *overlay2_mount_layer(const char *id, const struct graphdriver *driver, const struct driver_mount_opts *mount_opts);
int overlay2_rm_layer(const char *id, const struct graphdriver *driver);
int overlay2_umount_layer(const char *id, const struct graphdriver *driver);
container_inspect_graph_driver *graphdriver_get_metadata(const char *id);
int graphdriver_apply_diff(const char *id, const struct io_read_wrapper *content);
int overlay2_apply_diff(const char *id, const struct graphdriver *driver, const struct io_read_wrapper *content);
char *graphdriver_mount_layer(const char *id, const struct driver_mount_opts *mount_opts);
int graphdriver_umount_layer(const char *id);
int graphdriver_rm_layer(const char *id);
void free_graphdriver_mount_opts(struct driver_mount_opts *opts);
#ifdef __cplusplus
}
#endif

#endif
