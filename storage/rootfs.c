#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include "rootfs.h"

#include "utils.h"
#include "fs.h"

#define CONTAINER_JSON "container.json"

struct rootfs_list_item {
	char *rootfs_id;
	char *layer;
	char **names;
	int names_len;
	cntrootfs_t *cntr;
	struct rootfs_list_item* next;
};

typedef struct rootfs_store {
	char *dir;
	struct rootfs_list_item* rootfs_list;
	size_t rootfs_list_len;
} rootfs_store_t;

rootfs_store_t *g_rootfs_store = NULL;

static int append_container_rootfs(const char *id, const char *layer, const char **unique_names, size_t unique_names_len, cntrootfs_t *cntr) {
	int ret = 0;
	size_t i = 0;
	struct rootfs_list_item *item = NULL;


	item = calloc_s(sizeof(struct rootfs_list_item), 1);
	if(item == NULL) {
		printf("Out of memory\n");
		return -1;
	}

	item->cntr = cntr;
	item->rootfs_id = strdup_s(id);
	item->layer = strdup_s(layer);
	item->names = (char**)malloc(sizeof(char*) * unique_names_len);
	for(i = 0;  i < unique_names_len; i++) {
		item->names[i] = strdup_s(unique_names[i]);
	}
	item->names_len = unique_names_len;
	item->next = g_rootfs_store->rootfs_list->next;
	g_rootfs_store->rootfs_list->next = item;
	g_rootfs_store->rootfs_list_len++;
	return ret;
}

static int copy_id_map(storage_rootfs *c, const struct storage_rootfs_options *rootfs_opts)
{
    int ret = 0; 
    size_t i;
    storage_rootfs_uidmap_element **uid_map = NULL;
    size_t uid_map_len = 0; 
    storage_rootfs_gidmap_element **gid_map = NULL;
    size_t gid_map_len = 0; 

    if (rootfs_opts == NULL) {
        return 0;
    }    

    if (rootfs_opts->id_mapping_opts.uid_map_len != 0) { 
        if (rootfs_opts->id_mapping_opts.uid_map_len >= SIZE_MAX / sizeof(storage_rootfs_uidmap_element *)) {
           	printf("Too many id map\n");
            return -1;
        }
        uid_map = (storage_rootfs_uidmap_element **)common_calloc_s(sizeof(storage_rootfs_uidmap_element *) * 
                                                                         rootfs_opts->id_mapping_opts.uid_map_len);
        if (uid_map == NULL) {
            printf("Out of memory\n");
            return -1;
        }

        for (i = 0; i < rootfs_opts->id_mapping_opts.uid_map_len; i++) {
            uid_map[i] = (storage_rootfs_uidmap_element *)common_calloc_s(sizeof(storage_rootfs_uidmap_element));
            if (uid_map[i] == NULL) {
                printf("Out of memory\n");
                ret = -1;
                goto out; 
            }
            uid_map[i]->container_id = rootfs_opts->id_mapping_opts.uid_map->container_id;
            uid_map[i]->host_id = rootfs_opts->id_mapping_opts.uid_map->host_id;
            uid_map[i]->size = rootfs_opts->id_mapping_opts.uid_map->size;
            uid_map_len++;
        }
    }    

    if (rootfs_opts->id_mapping_opts.gid_map_len != 0) { 
        if (rootfs_opts->id_mapping_opts.gid_map_len >= SIZE_MAX / sizeof(storage_rootfs_gidmap_element *)) {
            printf("Too many id map\n");
            return -1;
        }
        gid_map = (storage_rootfs_gidmap_element **)common_calloc_s(sizeof(storage_rootfs_gidmap_element *) * 
                                                                         rootfs_opts->id_mapping_opts.gid_map_len);
        if (gid_map == NULL) {
           	printf("Out of memory\n");
            return -1;
        }

        for (i = 0; i < rootfs_opts->id_mapping_opts.gid_map_len; i++) {
            gid_map[i] = (storage_rootfs_gidmap_element *)common_calloc_s(sizeof(storage_rootfs_gidmap_element));
            if (gid_map[i] == NULL) {
                printf("Out of memory\n");
                ret = -1;
                goto out;
            }
            gid_map[i]->container_id = rootfs_opts->id_mapping_opts.gid_map->container_id;
            gid_map[i]->host_id = rootfs_opts->id_mapping_opts.gid_map->host_id;
            gid_map[i]->size = rootfs_opts->id_mapping_opts.gid_map->size;
            gid_map_len++;
        }
    }

    c->uidmap = uid_map;
    c->uidmap_len = gid_map_len;
    uid_map = NULL;

    c->gidmap = gid_map;
    c->gidmap_len = gid_map_len;
    gid_map = NULL;

    return 0;

out:
    for (i = 0; i < uid_map_len; i++) {
        free(uid_map[i]);
        uid_map[i] = NULL;
    }
    free(uid_map);

    for (i = 0; i < gid_map_len; i++) {
        free(gid_map[i]);
        gid_map[i] = NULL;
    }
    free(gid_map);

    return ret;
}

static storage_rootfs *new_storage_rootfs(const char *id, const char *image, const char **unique_names,
                                          size_t unique_names_len, const char *layer, const char *metadata,
                                          struct storage_rootfs_options *rootfs_opts)
{
    int ret = 0; 
    char timebuffer[TIME_STR_SIZE] = { 0x00 };
    storage_rootfs *c = NULL;

    c = (storage_rootfs *)common_calloc_s(sizeof(storage_rootfs));
    if (c == NULL) {
        printf("Out of memory\n");
        return NULL;
    }    

    c->id = strdup_s(id);

    c->names = str_array_dup(unique_names, unique_names_len);
    c->names_len = unique_names_len;

    c->image = strdup_s(image);
    c->layer = strdup_s(layer);
    c->metadata = strdup_s(metadata);

    if (!get_now_time_buffer(timebuffer, sizeof(timebuffer))) {
        printf("Failed to get now time string");
        ret = -1;
        goto out; 
    }    
    c->created = strdup_s(timebuffer);

    if (copy_id_map(c, rootfs_opts) != 0) { 
        printf("Failed to copy UID&GID map");
        ret = -1;
        goto out; 
    }    

out:
    if (ret != 0) { 
        free(c);
        c = NULL;
    }    
    return c;
}

static void free_rootfs_t(cntrootfs_t *ptr) {
	if(ptr == NULL) {
		return;
	}
	free(ptr->srootfs);
	ptr->srootfs = NULL;
	free(ptr);
}

static cntrootfs_t *create_empty_cntr()
{
    cntrootfs_t *result = NULL;

    result = (cntrootfs_t *)calloc_s(sizeof(cntrootfs_t), 1); 
    if (result == NULL) {
        printf("Out of memory\n");
        goto err_out;
    }   
    result->refcnt = 1;

    return result;

err_out:
    free_rootfs_t(result);
    return NULL;
}

cntrootfs_t *new_rootfs(storage_rootfs *scntr)
{
    cntrootfs_t *c = NULL;

    if (scntr == NULL) {
        printf("Empty storage cntr\n");
        return NULL;
    }   

    c = create_empty_cntr();
    if (c == NULL) {
        return NULL;
    }   

    c->srootfs = scntr;

    return c;
}

static int get_container_path(const char *id, char *path, size_t len) {
	int  nret = snprintf(path, len, "%s/%s/%s", g_rootfs_store->dir, id, CONTAINER_JSON);
	return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
}

static int save_rootfs(cntrootfs_t *cntr)
{
    int ret = 0; 
    char container_path[PATH_MAX] = { 0x00 };
    char container_dir[PATH_MAX] = { 0x00 };
    parser_error err = NULL;
    char *json_data = NULL;

    if (get_container_path(cntr->srootfs->id, container_path, sizeof(container_path)) != 0) { 
     	printf("Failed to get container path by id: %s", cntr->srootfs->id);
        return -1;
    }    

    strcpy(container_dir, container_path);
    ret = mkdir_p(dirname(container_dir), 0666);
    if (ret < 0) { 
        printf("Failed to create container directory %s.\n", container_path);
        return -1;
    }    

    json_data = storage_rootfs_generate_json(cntr->srootfs, NULL, &err);
    if (json_data == NULL) {
        printf("Failed to generate container json path string:%s\n", err ? err : " ");
        ret = -1;
        goto out; 
    }    

    if (atomic_write_file(container_path, json_data, strlen(json_data), 0666, false) != 0) { 
        printf("Failed to save container json file\n");
        ret = -1;
        goto out; 
    }    

out:
    free(json_data);
    free(err);

    return ret; 
}

static cntrootfs_t *lookup(const char *id) {
	cntrootfs_t *cntr = NULL;
	char **names = NULL;
	int names_len = 0;
	int i = 0;
	struct rootfs_list_item *item = g_rootfs_store->rootfs_list->next;
	while(item != NULL) {
		if(strcmp(item->rootfs_id, id) == 0) {
			cntr = item->cntr;
			break;
		}
		names = item->names;
		names_len = item->cntr->srootfs->names_len;
		for(i = 0; i < names_len; i++) {
			if(strcmp(names[i], id) == 0) {
				cntr = item->cntr;
				goto out;
			}
		}
		item = item->next;
	}
out:
	return cntr;
}

int rootfs_store_get_all_rootfs(struct rootfs_list *all_rootfs) {
	size_t i = 0;
	struct rootfs_list_item *item = g_rootfs_store->rootfs_list->next;
	
	all_rootfs->rootfs = (storage_rootfs**)malloc(sizeof(storage_rootfs*) * g_rootfs_store->rootfs_list_len);
	while(item != NULL) {
		all_rootfs->rootfs[i++] = item->cntr->srootfs;
	}

	all_rootfs->rootfs_len = g_rootfs_store->rootfs_list_len;

	return 0;
}

void free_rootfs_list(struct rootfs_list *all_rootfs) {
	free(all_rootfs->rootfs);
	free(all_rootfs);
}

static int remove_rootfs_from_memory(char *id) {
	printf("=============remove_rootfs_from_memory================\n");
	struct rootfs_list_item *item = g_rootfs_store->rootfs_list;
	
	while(item->next != NULL) {
		if(strcmp(item->next->rootfs_id, id) == 0) {
			break;
		}
	}
	if(item->next == NULL) {
		return -1;
	}
	struct rootfs_list_item *d = item->next;
	item->next = item->next->next;
	free(d->rootfs_id);
	free(d->layer);
	free_array_by_len(d->names, d->names_len);
	printf("*****************remove_rootfs_from_memory*************\n");
	return 0;
}

static inline int get_data_dir(const char *id, char *path, size_t len)
{
    int nret = snprintf(path, len, "%s/%s", g_rootfs_store->dir, id);
    return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
}

static int remove_rootfs_dir(const char *id) 
{
    char rootfs_path[PATH_MAX] = { 0x00 };

    if (get_data_dir(id, rootfs_path, sizeof(rootfs_path)) != 0) { 
        printf("Failed to get rootfs data dir: %s\n", id); 
        return -1;
    }    

    if (recursive_rmdir(rootfs_path, 0) != 0) { 
        printf("Failed to delete rootfs directory : %s\n", rootfs_path);
        return -1;
    }    

    return 0;
}

int delete_rootfs_from_store(const char *id) {
	printf("=================delete_rootfs_from_store===================\n");
	int ret = 0;
	cntrootfs_t *cntr = NULL;

	if(id == NULL) {
		printf("Invalid input parameter : empty id\n");
		return -1;
	}

	if(g_rootfs_store == NULL) {
		printf("Rootfs store is not ready\n");
		return -1;
	}

	cntr = lookup(id);
	if(cntr == NULL) {
		printf("Rootfs %s not known\n", id);
		return -1;
	}

	if(remove_rootfs_from_memory(cntr->srootfs->id) != 0) {
		printf("Failed to remove rootfs from memory\n");
		ret = -1;
		goto out;
	}

	if(remove_rootfs_dir(cntr->srootfs->id) != 0) {
		printf("Failed to delete rootfs directory\n");
		ret = -1;
		goto out;
	}
out:
	printf("******************delete_rootfs_from_store*******************\n");
	return ret;
}

char *rootfs_store_create(const char *id, const char **names, size_t names_len, const char *image, const char *layer,
                          const char *metadata, struct storage_rootfs_options *rootfs_opts)
{
    int ret = 0;
    char *dst_id = NULL;
    char **unique_names = NULL;
    size_t unique_names_len = 0;
    cntrootfs_t *cntr = NULL;
    storage_rootfs *c = NULL;

    /*if (g_rootfs_store == NULL) {
        printf("Container store is not ready\n");
        return NULL;
    }*/

    if (id == NULL) {
        //dst_id = generate_random_container_id();
    } else {
        dst_id = strdup_s(id);
    }

    if (dst_id == NULL) {
        printf("Out of memory or generate random container id failed\n");
        ret = -1;
        goto out;
    }

    /*if (map_search(g_rootfs_store->byid, (void *)dst_id) != NULL) {
        ERROR("ID is already in use: %s", dst_id);
        ret = -1;
        goto out;
    }*/

    /*if (util_string_array_unique(names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }*/

    c = new_storage_rootfs(dst_id, image, names, names_len, layer, metadata, rootfs_opts);
    if (c == NULL) {
        printf("Failed to generate new storage container\n");
        ret = -1;
        goto out;
    }

    cntr = new_rootfs(c);
    if (cntr == NULL) {
        printf("Out of memory\n");
        ret = -1;
        goto out;
    }
    c = NULL;

    if (append_container_rootfs(dst_id, layer, (const char **)names, names_len, cntr) != 0) {
        printf("Failed to append container to container store");
        ret = -1;
        goto out;
    }

    if (save_rootfs(cntr) != 0) {
        printf("Failed to save container\n");
        if (delete_rootfs_from_store(dst_id) != 0) {
            printf("Failed to delete rootfs from store\n");
        }
        c = NULL;
        cntr = NULL;
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free(dst_id);
        dst_id = NULL;
        free_storage_rootfs(c);
        c = NULL;
        free_rootfs_t(cntr);
        cntr = NULL;
    }
    return dst_id;
}

static storage_rootfs *copy_rootfs(const storage_rootfs *rootfs)
{
    char *json = NULL;
    parser_error err = NULL;
    storage_rootfs *ans = NULL;

    if (rootfs == NULL) {
        return NULL;
    }

    json = storage_rootfs_generate_json(rootfs, NULL, &err);
    if (json == NULL) {
        printf("Failed to generate json: %s\n", err);
        goto out;
    }
    ans = storage_rootfs_parse_data(json, NULL, &err);
    if (ans == NULL) {
        printf("Failed to parse json: %s\n", err);
        goto out;
    }

out:
    free(err);
    free(json);
    return ans;
}

storage_rootfs *rootfs_store_get_rootfs(const char *id) 
{
	printf("================rootfs_store_get_rootfs=================\n");
    cntrootfs_t *cntr = NULL;
    storage_rootfs *dup_rootfs = NULL;

    if (id == NULL) {
        printf("Invalid parameter, id is NULL\n");
        return NULL;
    }    

    if (g_rootfs_store == NULL) {
        printf("Rootfs store is not ready\n");
        return NULL;
    }    

    cntr = lookup(id);
    if (cntr == NULL) {
        printf("Rootfs not known\n");
        goto out; 
    }    

    dup_rootfs = copy_rootfs(cntr->srootfs);

out:
    //rootfs_ref_dec(cntr);
    //rootfs_store_unlock();
	printf("********************rootfs_store_get_rootfs**********************\n");
    return dup_rootfs;
}

char *rootfs_store_get_id(const char *name) {
	storage_rootfs *rootfs = NULL;
	rootfs = rootfs_store_get_rootfs(name);
	if(rootfs == NULL) {
		return NULL;
	}

	if(rootfs->id == NULL) {
		printf("Invalid rootfs %s id = NULL\n", name);
	}
	return strdup_s(rootfs->id);
}

static int do_append_container(storage_rootfs *c) {
	cntrootfs_t *cntr = NULL;
	
	cntr = new_rootfs(c);
	if(cntr == NULL) {
		printf("Out of memory\n");
		return -1;
	}

	if (append_container_rootfs(c->id, c->layer, (const char**)(c->names), c->names_len, cntr) != 0) {
        printf("Failed to append container to container store\n");
    	return -1;
	}

	return 0;
}

static int append_container_by_directory(const char *container_dir)
{
    int ret = 0; 
    int nret;
    char container_path[PATH_MAX] = { 0x00 };
    storage_rootfs *c = NULL;
    parser_error err = NULL;

    nret = snprintf(container_path, sizeof(container_path), "%s/%s", container_dir, CONTAINER_JSON);
    if (nret < 0 || (size_t)nret >= sizeof(container_path)) {
        // snprintf error, not append, but outside should not delete the rootfs
        printf("Failed to get container path\n");
        return -1;
    }    

    c = storage_rootfs_parse_file(container_path, NULL, &err);
    if (c == NULL) {
        printf("Failed to parse container path: %s\n", err);
        ret = -1;
        goto out; 
    }    

    if (do_append_container(c) != 0) { 
        // append error should not return -1, outside should not remove rootfs
        printf("Failed to append container\n");
        ret = -1;
        goto out; 
    }    

    c = NULL;

out:
    free_storage_rootfs(c);
    free(err);
    return ret; 
}

static int rootfs_store_load() {
	int ret = 0;
	int nret = 0;
	int append_ret = 0;
	char **container_dirs = NULL;
	size_t container_dirs_num = 0;
	size_t i = 0;
	char container_path[PATH_MAX] = { 0x00 };

	ret = list_all_subdir(g_rootfs_store->dir, &container_dirs, &container_dirs_num);
	if(ret != 0) {
		printf("Failed to get container directories\n");
		goto out;
	}

	for(i = 0; i < container_dirs_num; i++) {
		printf("Restore the containers:%s\n", container_dirs[0]);
		nret = snprintf(container_path, sizeof(container_path), "%s/%s", g_rootfs_store->dir, container_dirs[i]);
		if(nret < 0 || (size_t)nret >= sizeof(container_path)) {
			printf("Failed to get container path\n");
			continue;
		}
		append_ret = append_container_by_directory(container_path);
		if(append_ret != 0) {
			printf("Found container path but load failed: %s, deleting...\n", container_path);
			if(recursive_rmdir(container_path, 0) != 0) {
				printf("Failed to delete rootfs directory : %s\n", container_path);
			}
			continue;
		}
	}
out:
	free_array_by_len(container_dirs, container_dirs_num);
	return ret;
}

static void free_rootfs_store(rootfs_store_t *store) {
	struct rootfs_list_item *elem, *nxt;

	if(store == NULL) {
		return;
	}

	free(store->dir);
	store->dir = NULL;

	elem = store->rootfs_list;
	while(elem) {
		nxt = elem->next;
		free(elem);
		elem = nxt;
	}

	store->rootfs_list_len = 0;
	free(store);
}

int rootfs_store_init() {
	int ret = 0;

	if(g_rootfs_store == NULL) {
		g_rootfs_store = (rootfs_store_t*)malloc(sizeof(rootfs_store_t));
		g_rootfs_store->rootfs_list_len = 0;
		g_rootfs_store->rootfs_list = calloc_s(sizeof(struct rootfs_list_item), 1);
		g_rootfs_store->rootfs_list->next = NULL;
		g_rootfs_store->dir = "/var/lib/docker-mini/overlay-containers";
	}

	ret = mkdir_p(g_rootfs_store->dir, 0666);
	if(ret < 0) {
		printf("Unable to create container store directory %s.\n", g_rootfs_store->dir);
		ret = -1;
		goto out;
	}
	
	ret = rootfs_store_load();
	if(ret != 0) {
		printf("Failed to load container store\n");
		ret = -1;
		goto out;
	}

out:
	if(ret != 0) {
		free_rootfs_store(g_rootfs_store);
		g_rootfs_store = NULL;
	}
	return ret;
}

