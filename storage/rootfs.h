#ifndef __ROOTFS_H__
#define __ROOTFS_H__

#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "storage.h"
#include "storage_rootfs.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct _cntrootfs_t {
	storage_rootfs *srootfs;
	uint64_t refcnt;
} cntrootfs_t;

struct rootfs_list {
	int rootfs_len;
	storage_rootfs **rootfs;
};

int rootfs_store_init();

cntrootfs_t *new_rootfs(storage_rootfs *scntr);
int delete_rootfs_from_store(const char *id);
char *rootfs_store_create(const char *id, const char **names, size_t names_len, const char *image, const char *layer,
                          const char *metadata, struct storage_rootfs_options *rootfs_opts);
storage_rootfs *rootfs_store_get_rootfs(const char *id);
char *rootfs_store_get_id(const char *name);
int rootfs_store_get_all_rootfs(struct rootfs_list *all_rootfs);
void free_rootfs_list(struct rootfs_list *rootfs_list);

#ifdef __cplusplus
}
#endif

#endif
