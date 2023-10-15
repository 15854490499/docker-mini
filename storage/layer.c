#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "layer.h"
#include "log.h"
#include "timestamp.h"
#include "archive.h"

struct layer_list_elem {
	char *layer_id;
	layer_t *layer;
	struct layer_list_elem *next;
};

typedef struct __layer_store_metadata_t {
	struct layer_list_elem *layer_list;
	size_t layer_list_len;
} layer_store_metadata;

layer_store_metadata *g_metadata = NULL;

#define g_root_dir "/var/lib/docker-mini/overlay-layers"
#define g_run_dir "/var/lib/docker-mini/run"

static int driver_create_layer(const char *id, const char *parent, bool writable, const struct layer_store_mount_opts *opt) {
	struct driver_create_opts c_opts = { 0 };
	int ret = 0;
	size_t i = 0;
	if(opt != NULL) {
		c_opts.mount_label = strdup_s(opt->mount_label);
        if (opt->mount_opts != NULL) {
            c_opts.storage_opt = calloc_s(1, sizeof(json_map_string_string));
            if (c_opts.storage_opt == NULL) {
            	LOG_ERROR("Out of memory\n");
                ret = -1;
                goto free_out;
            }
            for (i = 0; i < opt->mount_opts->len; i++) {
                ret = append_json_map_string_string(c_opts.storage_opt, opt->mount_opts->keys[i],
                                                    opt->mount_opts->values[i]);
                if (ret != 0) { 
                	LOG_ERROR("Out of memory\n");
                    goto free_out;
                }
            }
        }
    }    

    if (writable) {
        ret = graphdriver_create_rw(id, parent, &c_opts);
    } else {
        ret = graphdriver_create_ro(id, parent, &c_opts);
    }    
    if (ret != 0) { 
        if (id != NULL) {
        	LOG_ERROR("error creating %s layer with ID %s\n", writable ? "read-write" : "read-only", id); 
        } else {
        	LOG_ERROR("error creating %s layer\n", writable ? "read-write" : ""); 
        }
        goto free_out;
    }    

free_out:
    free(c_opts.mount_label);
    free_json_map_string_string(c_opts.storage_opt);
    return ret; 
}

layer_t *create_empty_layer() {
	layer_t *res = NULL;
	int nret = 0;

	res = (layer_t*)calloc_s(sizeof(layer_t), 1);
	if(res == NULL) {
		LOG_ERROR("Out of memory\n");
		goto err_out;
	}
	res->refcnt = 1;
	return res;
err_out:
	free(res);
	return  NULL;
}

static inline char *layer_json_path(const char *id) {
	char *res = NULL;
	int nret = 0;
	
	res = (char*)common_calloc_s(PATH_MAX);
	nret = sprintf(res, "%s/%s/layer.json", g_root_dir, id);
	if(nret < 0 || nret > PATH_MAX) {
		LOG_ERROR("Create tar split path failed\n");
		return NULL;
	}
	return res;
}

static int update_layer_datas(const char *id, const struct layer_opts *opts, layer_t *l)
{
    int ret = 0; 
    storage_layer *slayer = NULL;
    char timebuffer[TIME_STR_SIZE] = { 0 }; 
    size_t i = 0; 

    slayer = calloc_s(sizeof(storage_layer), 1);
    if (slayer == NULL) {
    	LOG_ERROR("Out of memory\n");
        ret = -1;
        goto free_out;
    }    

    slayer->id = strdup_s(id);
    slayer->parent = strdup_s(opts->parent);
    slayer->writable = opts->writable;
    if (opts->opts != NULL) {
        slayer->mountlabel = strdup_s(opts->opts->mount_label);
    }    
    if (!get_now_local_utc_time_buffer(timebuffer, TIME_STR_SIZE)) {
    	LOG_ERROR("Get create time failed");
        ret = -1;
        goto free_out;
    }    
    slayer->created = strdup_s(timebuffer);

    if (opts->names_len > 0) { 
        slayer->names = calloc_s(1, sizeof(char *) * opts->names_len);
        if (slayer->names == NULL) {
        	LOG_ERROR("Out of memory");
            ret = -1;
            goto free_out;
        }
    }
    for (i = 0; i < opts->names_len; i++) {
        slayer->names[i] = strdup_s(opts->names[i]);
        slayer->names_len++;
    }
    slayer->diff_digest = strdup_s(opts->uncompressed_digest);
    slayer->compressed_diff_digest = strdup_s(opts->compressed_digest);
    l->layer_json_path = layer_json_path(id);
    if (l->layer_json_path == NULL) {
        ret = -1;
        goto free_out;
    }

    l->slayer = slayer;

free_out:
    if (ret != 0) {
        free_storage_layer(slayer);
    }
    return ret;
}

static bool build_layer_dir(const char *id) {
	char *result = NULL;
	int nret = 0;
	bool ret = true;
	
	result = (char*)common_calloc_s(PATH_MAX);
	nret = sprintf(result, "%s/%s", g_root_dir, id);
	if(nret < 0 || nret > PATH_MAX) {
		LOG_ERROR("create layer json path failed\n");
		return false;
	}

	if(mkdir_p(result, 0766) != 0) {
		ret = false;
	}
	free(result);
	return ret;
}

static bool append_layer_into_list(layer_t *l) {
	struct layer_list_elem *elem = NULL;

	if(l == NULL)
		return true;
	elem = (struct layer_list_elem*)calloc_s(sizeof(struct layer_list_elem), 1);
	if(elem == NULL) {
		LOG_ERROR("Out of memory\n");
		return false;
	}
	elem->layer_id = l->slayer->id;
	elem->layer = l;
	elem->next = g_metadata->layer_list->next;
	g_metadata->layer_list->next = elem;
	g_metadata->layer_list_len += 1;
	return true;
}

static bool delete_layer_from_list(layer_t *l) {
	struct layer_list_elem *elem;
	if(l == NULL) {
		return true;
	}
	elem = g_metadata->layer_list;
	while(elem->next) {
		if(strcmp(elem->next->layer_id, l->slayer->id) == 0) {
			elem->next = elem->next->next;
			break;
		}
		elem = elem->next;
	}
	if(elem == NULL) {
		LOG_ERROR("Cannot find the target layer\n");
		return false;
	}
	return true;
}

static layer_t *lookup(const char *id) {
	if(g_metadata == NULL) {
		return NULL;
	}
	layer_t *l = NULL;
	struct layer_list_elem *elem = g_metadata->layer_list->next;
	while(elem != NULL) {
		if(strcmp(elem->layer_id, id) == 0) {
			l = elem->layer;
			break;
		}
		elem = elem->next;
	}
	return l;
}

static int save_mount_point(layer_t *layer)
{
    char *jstr = NULL;
    parser_error jerr;
    int ret = -1; 

    if (layer == NULL || layer->mount_point_json_path == NULL || layer->smount_point == NULL) {
        return ret;
    }   

    jstr = storage_mount_point_generate_json(layer->smount_point, NULL, &jerr);
    if (jstr == NULL) {
    	LOG_ERROR("Marsh mount point failed: %s\n", jerr);
        goto out;
    }   

    ret = atomic_write_file(layer->mount_point_json_path, jstr, strlen(jstr), 0666, false);
out:
    free(jstr);
    free(jerr);
    return ret;
}

static int umount_helper(layer_t *l, bool force) {
	int ret = 0;

	if(l->smount_point == NULL) {
		return 0;
	}

	ret = graphdriver_umount_layer(l->slayer->id);
	if(ret != 0) {
		LOG_ERROR("Call driver umount failed\n");
		ret = -1;
		goto out;
	}
save_json:
	save_mount_point(l);
out:
	return ret;
}

int layer_store_umount(const char *id, bool force) {
	layer_t *l = NULL;
	int ret = 0;

	if(id == NULL) {
		return 0;
	}
	l = lookup(id);
	if(l == NULL) {
		LOG_ERROR("layer not known, skip umount\n");
		return 0;
	}
	ret = umount_helper(l, force);
	return ret;
}

static int remove_memory_stores(const char *id) {
	layer_t *l = NULL;
	l = lookup(id);
	if(l == NULL) {
		LOG_ERROR("cannot find the target layer by id %s\n", id);
		return -1;
	}
	if(!delete_layer_from_list(l)) {
		return -1;
	}
	return 0;
}

static inline char *tar_split_tmp_path(const char *id) {
	char *result = NULL;
	int nret = 0;

	result = (char*)common_calloc_s(PATH_MAX);
	nret = sprintf(result, "%s/%s/%s.tar-split", g_root_dir, id, id);
    if (nret < 0 || nret > PATH_MAX) {
		free(result);
        return NULL;
    } 

	return result;
}

static inline char *tar_split_path(const char *id) {
	char *result = NULL;
	int nret = 0;

	result = (char*)common_calloc_s(PATH_MAX);
	nret = sprintf(result, "%s/%s/%s.tar-split.gz", g_root_dir, id, id);
    if (nret < 0 || nret > PATH_MAX) {
		free(result);
        return NULL;
    } 

	return result;
}

static int layer_store_remove_layer(const char *id) {
	char *rpath = NULL;
	int ret = 0;
	int  nret = 0;

	if(id == NULL) {
		return 0;
	}
	
	rpath = (char*)common_calloc_s(PATH_MAX);
	nret = sprintf(rpath, "%s/%s", g_root_dir, id);
	if(nret < 0 || nret > PATH_MAX) {
		LOG_ERROR("Create layer json path failed\n");
		return -1;
	}

	ret = recursive_rmdir(rpath, 0);
	free(rpath);
	return ret;
}

int layer_store_delete(const char *id) {
	int ret = 0;
	char *tspath = NULL;
	layer_t *l = NULL;

	if(id == NULL) {
		return -1;
	}

	l = lookup(id);
	if(l == NULL) {
		LOG_ERROR("layer %s not exists already, return success\n", id);
		goto free_out;
	}

	if(umount_helper(l, true) != 0) {
		ret = -1;
		LOG_ERROR("Failed to umount layer %s\n", l->slayer->id);
		goto free_out;
	}
	if (l->mount_point_json_path != NULL && path_remove(l->mount_point_json_path) != 0) {
    	LOG_ERROR("Can not remove mount point file of layer %s, just ignore.\n", l->mount_point_json_path);
    }

	tspath = tar_split_path(l->slayer->id);
	if(tspath != NULL && path_remove(tspath) != 0) {
		LOG_ERROR("Can not remove layer files, just ignore\n");
	}

	ret = remove_memory_stores(l->slayer->id);
	if(ret != 0) {
		goto free_out;
	}

	ret = graphdriver_rm_layer(l->slayer->id);
	if(ret != 0) {
		LOG_ERROR("Remove layer : %s by driver failed\n", l->slayer->id);
		goto free_out;
	}

	ret = layer_store_remove_layer(l->slayer->id);

free_out:
	free(tspath);
	return ret;
}

static int insert_memory_stores(const char *id, const struct layer_opts *opts, layer_t *l)
{
    int ret = 0; 
    int i = 0; 

    if (!append_layer_into_list(l)) {
        ret = -1;
        goto out; 
    }    

out:
    return ret;
}

static int new_layer_by_opts(const char *id, const struct layer_opts *opts) {
	int ret = 0;
	layer_t *l = NULL;

	l = create_empty_layer();
	if(l == NULL) {
		ret = -1;
		goto out;
	}
	if(!build_layer_dir(id)) {
		ret = -1;
		goto out;
	}
	ret = update_layer_datas(id, opts, l);
	if(ret != 0) {
		goto out;
	}

	ret = insert_memory_stores(id, opts, l);
out:
	return ret;
}

static int make_tar_split_file(const char *lid, const struct io_read_wrapper *diff, int64_t *size)
{
    int *pfd = (int *)diff->context;
    char *save_fname = NULL;
    char *save_fname_gz = NULL;
    int ret = -1;
	int nret = 0;
    int tfd = -1;
    //save_fname = tar_split_tmp_path(lid);
	save_fname = tar_split_tmp_path(lid);
	if(save_fname == NULL) {
		return -1;
	}

	save_fname_gz = tar_split_path(lid);
	if(save_fname_gz == NULL) {
		goto out;
	}

    // step 1: read header;
    tfd = open(save_fname, O_WRONLY | O_CREAT, 0666);
    if (tfd == -1) {
    	LOG_ERROR("touch file failed");
        goto out; 
    }    
    close(tfd);
    tfd = -1;

    // step 2: build entry json;
    // step 3: write into tar split;
    ret = archive_copy_oci_tar_split_and_ret_size(*pfd, save_fname, size);
    if (ret != 0) { 
        goto out; 
    }    

    // not exist entry for layer, just return 0
    if (!file_exists(save_fname)) {
        goto out; 
    }    

    // step 4: gzip tar split, and save file.
    ret = gzip_z(save_fname, save_fname_gz, 0666);

    // always remove tmp tar split file, even though gzip failed.
    // if remove failed, just log message
    if (path_remove(save_fname) != 0) { 
    	LOG_ERROR("remove tmp tar split failed");
    }    

out:
    free(save_fname_gz);
    free(save_fname);
    return ret;
}

static int apply_diff(layer_t *l, const struct io_read_wrapper *diff) {
	int64_t size = 0;
	int ret = 0;

	if(diff == NULL) {
		return 0;
	}

	ret = graphdriver_apply_diff(l->slayer->id, diff);
	if(ret != 0) {
		goto out;
	}
	
	ret = make_tar_split_file(l->slayer->id, diff, &size);
	l->slayer->diff_size = size;
out:
	return ret;
}

static inline char *mountpoint_json_path(const char *id) {
	char *result = NULL;
	int nret = 0;

	result = (char*)common_calloc_s(PATH_MAX);
	nret = sprintf(result, "%s/%s.json", g_run_dir, id);
	if(nret < 0 || nret > PATH_MAX) {
		LOG_ERROR("Create mount point json path failed\n");
		return NULL;
	}
	return result;
}

static int update_mount_point(layer_t *l)
{
    container_inspect_graph_driver *d_meta = NULL;
    int ret = 0; 

    if (l->smount_point == NULL) {
        l->smount_point = calloc_s(sizeof(storage_mount_point), 1);
        if (l->smount_point == NULL) {
        	LOG_ERROR("Out of memory\n");
            return -1;
        }
    }    

    d_meta = graphdriver_get_metadata(l->slayer->id);
    if (d_meta == NULL) {
    	LOG_ERROR("Get metadata of driver failed\n");
        ret = -1;
        goto out; 
    }    
    if (d_meta->data != NULL) {
        free(l->smount_point->path);
        l->smount_point->path = strdup_s(d_meta->data->merged_dir);
    }    

    if (l->mount_point_json_path == NULL) {
        l->mount_point_json_path = mountpoint_json_path(l->slayer->id);
        if (l->mount_point_json_path == NULL) {
        	LOG_ERROR("Failed to get layer %s mount point json\n", l->slayer->id);
            ret = -1;
            goto out; 
        }
    }    

out:
    free_container_inspect_graph_driver(d_meta);
    return ret; 
}

static int save_layer(layer_t *layer) {
	char *jstr = NULL;
	parser_error jerr = NULL;
	int ret = -1;

	if(layer == NULL || layer->layer_json_path == NULL || layer->slayer == NULL) {
		LOG_ERROR("Invalid arguments\n");
		return ret;
	}
	jstr = storage_layer_generate_json(layer->slayer, NULL, &jerr);
	if(jstr == NULL) {
		LOG_ERROR("Marsh layer failed : %s\n", jerr);
		goto out;
	}
	ret = atomic_write_file(layer->layer_json_path, jstr, strlen(jstr), 0666, false);
	if(ret != 0) {
		LOG_ERROR("atomic write layer : %s failed\n", layer->slayer->id);
	}
out:
	free(jstr);
	free(jerr);
	return ret;
}

int layer_store_create(const char *id, const struct layer_opts *opts, const struct io_read_wrapper *diff, char **new_id) {
	int ret = 0;
	char *lid = NULL;
	layer_t *l = NULL;
	if(opts == NULL) {
		LOG_ERROR("Invalid argument\n");
		return -1;
	}
	lid = strdup_s(id);
	l = lookup(lid);
	if(l != NULL) {
		l->hold_refs_num++;
		goto free_out;
	}
	ret = driver_create_layer(lid, opts->parent, opts->writable, opts->opts);
	if(ret != 0) {
		goto free_out;
	}
	ret = new_layer_by_opts(lid, opts);
	if(ret != 0) {
		goto free_out;
	}

	l = lookup(lid);
	if(l == NULL) {
		ret = -1;
		goto clear_memory;
	}
	l->slayer->incomplete = true;
	if(save_layer(l) != 0) {
		ret = -1;
		goto clear_memory;
	}
	ret = apply_diff(l, diff);
	if(ret != 0) {
		goto clear_memory;
	}
	ret = update_mount_point(l);
	if(ret != 0) {
		goto clear_memory;
	}
	l->slayer->incomplete = false;
	ret = save_layer(l);
	if(ret == 0) {
		if(new_id != NULL) {
			*new_id = lid;
			lid = NULL;
		}
		l->hold_refs_num++;
		goto free_out;
	}
	LOG_ERROR("save layer failed\n");
clear_memory:
	remove_memory_stores(lid);
free_out:
	free(lid);
	return ret;
}

static void copy_json_to_layer(const layer_t *jl, struct layer *l)
{
    if (jl->slayer == NULL) {
        return;
    }    
    l->id = strdup_s(jl->slayer->id);
    l->parent = strdup_s(jl->slayer->parent);
    l->compressed_digest = strdup_s(jl->slayer->compressed_diff_digest);
    l->compress_size = jl->slayer->compressed_size;
    l->uncompressed_digest = strdup_s(jl->slayer->diff_digest);
    l->uncompress_size = jl->slayer->diff_size;
    if (jl->smount_point != NULL) {
        l->mount_point = strdup_s(jl->smount_point->path);
        l->mount_count = jl->smount_point->count;
    }    
    l->writable = jl->slayer->writable;
}

struct layer *layer_store_lookup(const char *name) {
	struct layer *ret = NULL;
	layer_t *l = NULL;

	if(name == NULL)
		return ret;

	l = lookup(name);
	if(l == NULL) {
		return ret;
	}

	ret = common_calloc_s(sizeof(struct layer));
	if(ret == NULL) {
		LOG_ERROR("Out of memory\n");
		return ret;
	}
	
	copy_json_to_layer(l, ret);
	return ret;
}

static struct driver_mount_opts *fill_driver_mount_opts(const layer_t *l)
{
    struct driver_mount_opts *d_opts = NULL;

    d_opts = common_calloc_s(sizeof(struct driver_mount_opts));
    if (d_opts == NULL) {
    	LOG_ERROR("Out of meoroy\n");
        goto err_out;
    }

    if (l->slayer->mountlabel != NULL) {
        d_opts->mount_label = strdup_s(l->slayer->mountlabel);
    }

    return d_opts;

err_out:
    free_graphdriver_mount_opts(d_opts);
    return NULL;
}

static char *mount_helper(layer_t *l)
{
    char *mount_point = NULL;
    int nret = 0;
    struct driver_mount_opts *d_opts = NULL;

    nret = update_mount_point(l);
    if (nret != 0) {
    	LOG_ERROR("Failed to update mount point\n");
        return NULL;
    }

    if (l->smount_point->count > 0) {
        l->smount_point->count += 1;
        mount_point = strdup_s(l->smount_point->path);
        goto save_json;
    }

    d_opts = fill_driver_mount_opts(l);
    if (d_opts == NULL) {
    	LOG_ERROR("Failed to fill layer %s driver mount opts\n", l->slayer->id);
        goto out;
    }

    mount_point = graphdriver_mount_layer(l->slayer->id, d_opts);
    if (mount_point == NULL) {
    	LOG_ERROR("Call driver mount: %s failed\n", l->slayer->id);
        goto out;
    }

    l->smount_point->count += 1;

save_json:
    (void)save_mount_point(l);

out:
    free_graphdriver_mount_opts(d_opts);
    return mount_point;
}

char *layer_store_mount(const char *id) 
{
    layer_t *l = NULL;
    char *result = NULL;

    if (id == NULL) {
    	LOG_ERROR("Invalid arguments\n");
        return NULL;
    }    

    l = lookup(id);
    if (l == NULL) {
    	LOG_ERROR("layer not known\n");
        return NULL;
    }    
    result = mount_helper(l);
    if (result == NULL) {
    	LOG_ERROR("Failed to mount layer %s\n", id); 
    }    

    return result;
}

layer_t *load_layer(const char *fname, const char *mountpoint_fname) {
	parser_error err = NULL;
	layer_t *result = NULL;
	storage_layer *slayer = NULL;
	storage_mount_point *smount_point = NULL;

	if(fname == NULL) {
		return result;
	}
	slayer = storage_layer_parse_file(fname, NULL, &err);
	if(slayer == NULL) {
		LOG_ERROR("Parse layer failed: %s\n", err);
		goto free_out;
	}

	if(mountpoint_fname != NULL && file_exists(mountpoint_fname)) {
		smount_point = storage_mount_point_parse_file(mountpoint_fname, NULL, &err);
		if(smount_point == NULL) {
			LOG_ERROR("Parse mount point failed : %s\n", err);
			goto free_out;
		}
	}

	result = create_empty_layer();
	if(result == NULL) {
		goto free_out;
	}
	result->layer_json_path = strdup_s(fname);
	result->mount_point_json_path = strdup_s(mountpoint_fname);
	result->slayer = slayer;
	result->smount_point = smount_point;

	return result;
free_out:
	free(err);
	free_storage_mount_point(smount_point);
	free_storage_layer(slayer);
	return NULL;
}

void free_layer_t(layer_t *ptr)
{
    if (ptr == NULL) {
        return;
    }   
    free_storage_mount_point(ptr->smount_point);
    ptr->smount_point = NULL;
    free_storage_layer(ptr->slayer);
    ptr->slayer = NULL;
	if(ptr->layer_json_path != NULL) {
    	free(ptr->layer_json_path);
    	ptr->layer_json_path = NULL;
	}
	if(ptr->mount_point_json_path != NULL) {
   		free(ptr->mount_point_json_path);
    	ptr->mount_point_json_path = NULL;
	}
    free(ptr);
}

void free_layer(struct layer *l) {
	if(l == NULL) {
		return;
	}

	if(l->id != NULL) {
		free(l->id);
	}
	if(l->parent != NULL) {
		free(l->parent);
	}
	if(l->mount_point != NULL) {
		free(l->mount_point);
	}
	if(l->compressed_digest != NULL) {
		free(l->compressed_digest);
	}
	if(l->uncompressed_digest != NULL) {
		free(l->uncompressed_digest);
	}
	free(l);
}

static bool load_layer_json_cb(const char *path_name, struct dirent *sub_dir, void *context) {
#define LAYER_NAME_LEN 64
	bool flag = false;
	char tmpdir[PATH_MAX] = { 0 };
	int nret = 0;
	char *rpath = 0;
	char *mount_point_path = NULL;
	layer_t *l = NULL;

	nret = snprintf(tmpdir, PATH_MAX, "%s/%s", path_name, sub_dir->d_name);
	if(nret < 0 || nret >= PATH_MAX) {
		LOG_ERROR("sprintf: %s failed\n", sub_dir->d_name);
		goto free_out;
	}

	if(!dir_exists(tmpdir)) {
		LOG_ERROR("%s is not directory\n", sub_dir->d_name);
		goto free_out;
	}

	mount_point_path = mountpoint_json_path(sub_dir->d_name);
	if(mount_point_path == NULL) {
		LOG_ERROR("Out of memory\n");
		goto free_out;
	}

	if (strlen(sub_dir->d_name) != LAYER_NAME_LEN) {
    	LOG_ERROR("%s is invalid subdir name\n", sub_dir->d_name);
        goto free_out;
    }

    rpath = layer_json_path(sub_dir->d_name);
    if (rpath == NULL) {
    	LOG_ERROR("%s is invalid layer\n", sub_dir->d_name);
        goto free_out;
    }

    l = load_layer(rpath, mount_point_path);
    if (l == NULL) {
    	LOG_ERROR("load layer: %s failed, remove it\n", sub_dir->d_name);
        goto free_out;
    }

	if(!append_layer_into_list(l)) {
		LOG_ERROR("Failed to append layer info to list\n");
		goto free_out;
	}

	flag = true;
	goto free_out;

free_out:
	free(rpath);
	free(mount_point_path);
	if(!flag) {
		free_layer_t(l);
	}
	return true;
}

int layer_store_init() {
	int nret = 0;

	if(g_metadata == NULL) {
		g_metadata = (layer_store_metadata*)malloc(sizeof(layer_store_metadata));
		g_metadata->layer_list = (struct layer_list_elem*)malloc(sizeof(struct layer_list_elem));
		g_metadata->layer_list->next = NULL;
		g_metadata->layer_list_len = 0;
	}

	nret = mkdir_p(g_root_dir, 0600);
	if(nret != 0) {
		LOG_ERROR("build root dir of layer store failed\n");
		goto free_out;
	}
	
	nret = mkdir_p(g_run_dir, 0600);
	if(nret != 0) {
		LOG_ERROR("build run dir of layer failed\n");
		goto free_out;
	}

	nret = scan_subdirs(g_root_dir, load_layer_json_cb, NULL);
	if(nret != 0) {
		goto free_out;
	}
	nret = graphdriver_init();
	if(nret != 0) {
		LOG_ERROR("overlay2 driver init failed\n");
		goto free_out;
	}
	return 0;
free_out:
	return -1;
}
