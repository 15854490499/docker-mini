#include "driver.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <dirent.h>

#include "json_common.h"
#include "utils.h"
#include "archive.h"
#include "fs.h"
#include "log.h"
#include "project_quota.h"

#define DRIVER_OVERLAY_NAME "overlay"
#define DRIVER_OVERLAY2_NAME "overlay2"
#define OVERLAY_LINK_DIR "l"
#define OVERLAY_LAYER_DIFF "diff"
#define OVERLAY_LAYER_MERGED "merged"
#define OVERLAY_LAYER_WORK "work"
#define OVERLAY_LAYER_LOWER "lower"
#define OVERLAY_LAYER_LINK "link"
#define OVERLAY_LAYER_EMPTY "empty"

static const struct graphdriver_ops g_overlay2_ops = {
	/*.init = overlay2_init,
	.create_rw = overlay2_create_rw,
	.create_ro = overlay2_create_ro,*/
	.get_layer_metadata = overlay2_get_layer_metadata,
	.apply_diff = overlay2_apply_diff,
	.mount_layer = overlay2_mount_layer,
	.umount_layer = overlay2_umount_layer,
	.rm_layer = overlay2_rm_layer
};

static struct graphdriver g_driver = {
	.name = DRIVER_OVERLAY2_NAME,
	.ops = &g_overlay2_ops
};

static void check_link_file_valid(const char *fname) {
	int nret = 0;
	struct stat fstat;
	
	nret = stat(fname, &fstat);
	if(nret != 0) {
		if(errno == ENOENT) {
			LOG_INFO("[overlay2] : remove invalid symlink: %s\n", fname);
			if(path_remove(fname) != 0) {
				LOG_ERROR("Failed to remove link path %s\n", fname);
			}
		} else {
			LOG_ERROR("[overlay2]: Evaluate symlink %s failed\n", fname);
		}
	}
}

static void rm_invalid_symlink(const char *dirpath) {
	int nret = 0;
	struct dirent *pdirent = NULL;
	DIR *directory = NULL;
	char fname[PATH_MAX] = { 0 };

	directory = opendir(dirpath);
	if(directory == NULL) {
		LOG_ERROR("Failed to open %s\n", dirpath);
		return;
	}
	pdirent = readdir(directory);
	for(; pdirent != NULL; pdirent = readdir(directory)) {
		int  pathname_len;
		if(!strcmp(pdirent->d_name, ".") || !strcmp(pdirent->d_name, "..")) {
			continue;
		}
		memset(fname, 0, sizeof(fname));
		pathname_len = snprintf(fname, PATH_MAX, "%s/%s", dirpath, pdirent->d_name);
		if(pathname_len < 0 || pathname_len >= PATH_MAX) {
			LOG_ERROR("Pathname too long\n");
			continue;
		}
		check_link_file_valid(fname);
	}
	nret = closedir(directory);
	if(nret) {
		LOG_ERROR("Failed to close directory %s\n", dirpath);
	}
	return;
}

static int overlay2_create_home_directory(const char *_driver_home) {
	int ret = 0;
	char *link_dir = NULL;
	
	link_dir = path_join(_driver_home, OVERLAY_LINK_DIR);
	if(link_dir == NULL) {
		LOG_ERROR("unable to create overlay link directory %s.\n", _driver_home);
		return -1;
	}
	if(mkdir_p(link_dir, 0766) != 0) {
		LOG_ERROR("unable to create overlay home directory %s.\n", link_dir);
		ret = -1;
		goto out;
	}
	rm_invalid_symlink(link_dir);
out:
	free(link_dir);
	return ret;
}

static char *read_layer_lower_file(const char *layer_dir) {
	char *lower_file = NULL;
	char *lower = NULL;

	lower_file = path_join(layer_dir, OVERLAY_LAYER_LOWER);
	if(lower_file == NULL) {
		LOG_ERROR("Failed to get lower %s\n", layer_dir);
		goto out;
	}

	lower = read_text_file(lower_file);
out:
	free(lower_file);
	return lower;
}

static int append_abs_lower_path(const char *_driver_home, const char *lower, char ***abs_lowers) {
	int ret = 0;
	char *abs_path = NULL;

	abs_path = path_join(_driver_home, lower);
	if(!dir_exists(abs_path)) {
		LOG_ERROR("Can't stat absolute layer:%s\n", abs_path);
		ret = -1;
		goto out;
	}
	if(array_append(abs_lowers, abs_path) != 0) {
		LOG_ERROR("Can't append absolute layer:%s\n", abs_path);
		ret = -1;
		goto out;
	}
out:
	free(abs_path);
	return ret;
}

static int get_lower_dirs(const char *layer_dir, const struct graphdriver *driver, char **abs_lower_dir)
{
    int ret = 0;
	int nlen = 0;
    char *lowers_str = NULL;
    char **lowers = NULL;
    char **abs_lowers = NULL;
    size_t lowers_size = 0;
    size_t i = 0;

    lowers_str = read_layer_lower_file(layer_dir);
    lowers = string_split(lowers_str, ':', &nlen);
    lowers_size = array_len((const char **)lowers);
    if (lowers_size == 0) {
        ret = 0;
        goto out;
    }

    for (i = 0; i < nlen; i++) {
        if (append_abs_lower_path(driver->home, lowers[i], &abs_lowers) != 0) {
            ret = -1;
            goto out;
        }
    }

    *abs_lower_dir = string_join(":", (const char **)abs_lowers, array_len((const char **)abs_lowers));
    if (*abs_lower_dir == NULL) {
        ret = -1;
        goto out;
    }

out:
    free(lowers_str);
    free_array_by_len(lowers, nlen);
    free_array(abs_lowers);
    return ret;
}

int overlay2_get_layer_metadata(const char *id, const struct graphdriver *driver, json_map_string_string *map_info) {
	int ret = 0;
	char *layer_dir = NULL;
	char *work_dir = NULL;
	char *merged_dir = NULL;
	char *upper_dir = NULL;
	char *lower_dir = NULL;

	if(id == NULL || driver == NULL || map_info == NULL) {
		LOG_ERROR("invalid argument\n");
		ret = -1;
		goto out;
	}

	layer_dir = path_join(driver->home, id);
	if (layer_dir == NULL) {
    	LOG_ERROR("Failed to join layer dir:%s\n", id);
        ret = -1;
        goto out;
    }

    work_dir = path_join(layer_dir, OVERLAY_LAYER_WORK);
    if (work_dir == NULL) {
    	LOG_ERROR("Failed to join layer work dir:%s\n", layer_dir);
        ret = -1;
        goto out;
    }
    if (append_json_map_string_string(map_info, "WorkDir", work_dir) != 0) {
    	LOG_ERROR("Failed to append layer work dir:%s\n", work_dir);
        ret = -1;
        goto out; 
    }    

    merged_dir = path_join(layer_dir, OVERLAY_LAYER_MERGED);
    if (merged_dir == NULL) {
    	LOG_ERROR("Failed to join layer merged dir:%s\n", layer_dir);
        ret = -1;
        goto out; 
    }    
    if (append_json_map_string_string(map_info, "MergedDir", merged_dir) != 0) { 
    	LOG_ERROR("Failed to append layer merged dir:%s\n", merged_dir);
        ret = -1;
        goto out; 
    }    

    upper_dir = path_join(layer_dir, OVERLAY_LAYER_DIFF);
    if (upper_dir == NULL) {
    	LOG_ERROR("Failed to join layer upper_dir dir:%s\n", layer_dir);
        ret = -1;
        goto out;
    }
    if (append_json_map_string_string(map_info, "UpperDir", upper_dir) != 0) {
    	LOG_ERROR("Failed to append layer upper dir:%s\n", upper_dir);
        ret = -1;
        goto out;
    }

    if (get_lower_dirs(layer_dir, driver, &lower_dir) != 0) {
    	LOG_ERROR("Failed to get layer lower dir:%s\n", layer_dir);
        ret = -1;
        goto out;
    }
    if (lower_dir != NULL && append_json_map_string_string(map_info, "LowerDir", lower_dir) != 0) {
    	LOG_ERROR("Failed to append layer lower dir:%s\n", lower_dir);
        ret = -1;
        goto out;
    }

out:
    free(layer_dir);
    free(work_dir);
    free(merged_dir);
    free(upper_dir);
    free(lower_dir);
    return ret;
}

container_inspect_graph_driver *graphdriver_get_metadata(const char *id)
{
    int ret = -1; 
    int i = 0;
    container_inspect_graph_driver *inspect_driver = NULL;
    json_map_string_string *metadata = NULL;

    /*if (g_driver == NULL) {
    	LOG_ERROR("Driver not inited yet\n");
        return NULL;
    } */  

    if (id == NULL) {
    	LOG_ERROR("Invalid input arguments for get driver metadata\n");
        goto free_out;
    }   

    inspect_driver = calloc_s(sizeof(container_inspect_graph_driver), 1);
    if (inspect_driver == NULL) {
    	LOG_ERROR("Out of memory\n");
        goto free_out;
    }   

    inspect_driver->data = calloc_s(sizeof(container_inspect_graph_driver_data), 1);
    if (inspect_driver->data == NULL) {
    	LOG_ERROR("Out of memory\n");
        goto free_out;
    }   

    metadata = calloc_s(sizeof(json_map_string_string), 1);
    if (metadata == NULL) {
    	LOG_ERROR("Out of memory\n");
        goto free_out;
    }   

    /*if (!driver_rd_lock()) {
        goto free_out;
    }*/  

    ret = g_driver.ops->get_layer_metadata(id, &g_driver, metadata);
    if (ret != 0) {
    	LOG_ERROR("Failed to get metadata map info\n");
        goto free_out;
    }

    inspect_driver->name = strdup_s(g_driver.name);

    if (!strcmp(g_driver.name, DRIVER_OVERLAY_NAME) || !strcmp(g_driver.name, DRIVER_OVERLAY2_NAME)) {
        for (i = 0; i < metadata->len; i++) {
            if (!strcmp(metadata->keys[i], "LowerDir")) {
                inspect_driver->data->lower_dir = strdup_s(metadata->values[i]);
            } else if (!strcmp(metadata->keys[i], "MergedDir")) {
                inspect_driver->data->merged_dir = strdup_s(metadata->values[i]);
            } else if (!strcmp(metadata->keys[i], "UpperDir")) {
                inspect_driver->data->upper_dir = strdup_s(metadata->values[i]);
            } else if (!strcmp(metadata->keys[i], "WorkDir")) {
                inspect_driver->data->work_dir = strdup_s(metadata->values[i]);
            }
        }
    }/* else if (!strcmp(g_graphdriver->name, DRIVER_DEVMAPPER_NAME)) {
        for (i = 0; i < metadata->len; i++) {
            if (!strcmp(metadata->keys[i], "DeviceId")) {
                inspect_driver->data->device_id = util_strdup_s(metadata->values[i]);
            } else if (!strcmp(metadata->keys[i], "DeviceName")) {
                inspect_driver->data->device_name = util_strdup_s(metadata->values[i]);
            } else if (!strcmp(metadata->keys[i], "DeviceSize")) {
                inspect_driver->data->device_size = util_strdup_s(metadata->values[i]);
            } else if (!strcmp(metadata->keys[i], "MergedDir")) {
                inspect_driver->data->merged_dir = util_strdup_s(metadata->values[i]);
            }
        }
    }*/ else {
    	LOG_ERROR("Unsupported driver %s\n", g_driver.name);
        ret = -1;
        goto free_out;
    }

    ret = 0;

free_out:
    free_json_map_string_string(metadata);
    if (ret != 0) {
        free(inspect_driver);
        return NULL;
    }
    return inspect_driver;
}

int overlay2_apply_diff(const char *id, const struct graphdriver *driver, const struct io_read_wrapper *content) {
	int ret = 0;
	char *layer_dir = NULL;
	char *layer_diff = NULL;
	struct archive_options options = { 0 };
	char *err = NULL;
	
	if(id == NULL || driver == NULL || content == NULL) {
		LOG_ERROR("invalid argument\n");
		ret = -1;
		goto out;
	}

	layer_dir = path_join(driver_home, id);
	if(layer_dir == NULL) {
		LOG_ERROR("failed to join layer dir: %s\n", id);
		ret = -1;
		goto out;
	}

	layer_diff = path_join(layer_dir, OVERLAY_LAYER_DIFF);
	if(layer_diff == NULL) {
		LOG_ERROR("Failed to join layer diff dir: %s\n", id);
		ret = -1;
		goto out;
	}

	options.whiteout_format = OVERLAY_WHITEOUT_FORMATE;
	ret = archive_unpack(content, layer_diff, &options, &err);
	if(ret != 0) {
		LOG_ERROR("Failed to unpack to %s : %s", layer_diff, err);
		ret = -1;
		goto out;
	}
out:
	free(err);
	free(layer_dir);
	free(layer_diff);
	return ret;
}

int graphdriver_apply_diff(const char *id, const struct io_read_wrapper *content)
{
    int ret = 0;

    /*if (g_driver == NULL) {
    	LOG_ERROR("Driver not inited yet\n");
        return -1; 
    }*/  

    if (id == NULL || content == NULL) {
    	LOG_ERROR("Invalid input arguments for driver umount layer\n");
        return -1; 
    }   

    ret = g_driver.ops->apply_diff(id, &g_driver, content);

    return ret;
}

static bool check_bk_fs_support_quota(const char *backing_fs)
{
    return strcmp(backing_fs, "xfs") == 0 || strcmp(backing_fs, "extfs") == 0;
}

static int driver_init_quota(struct graphdriver *driver)
{
    int ret = 0; 

    if (check_bk_fs_support_quota(driver->backing_fs)) {
        driver->quota_ctrl = project_quota_control_init(driver->home, driver->backing_fs);
        if (driver->quota_ctrl != NULL) {
            driver->support_quota = true;
        } else if (driver->overlay_opts->default_quota != 0) { 
        	LOG_ERROR("Storage option overlay.size not supported. Filesystem does not support Project Quota\n");
            ret = -1;
            goto out; 
        }
    } else if (driver->overlay_opts->default_quota != 0) { 
    	LOG_ERROR("Storage option overlay.size only supported for backingFS XFS or ext4.\n");
        ret = -1;
        goto out; 
    }    

out:
    return ret; 
}

int graphdriver_init() {
	int ret = 0;
	char *root_dir = NULL;
	size_t i = 0;
	struct overlay_options *overlay_opts = NULL;
	overlay_opts = calloc_s(1, sizeof(struct overlay_options));
	if(overlay_opts == NULL) {
		LOG_ERROR("Out of memory\n");
		ret = -1;
		goto out;
	}
	g_driver.overlay_opts = overlay_opts;
	ret = overlay2_create_home_directory(driver_home);
	if(ret != 0) {
		return -1;
	}

	g_driver.home = strdup_s(driver_home);
	root_dir = path_dir(driver_home);
	if(root_dir == NULL) {
		LOG_ERROR("Unable to get overlay root home directory %s.\n", driver_home);
		return -1;
	}
	g_driver.backing_fs = get_fs_name(root_dir);
	if(g_driver.backing_fs == NULL) {
		LOG_ERROR("Failed to get overlay backing fs\n");
		ret = -1;
		goto out;
	}
	if(!support_d_type(driver_home)) {
		LOG_ERROR("The backing %s filesystem is formatted without d_type support, which leads to incorrect behavior\n", driver_home);
		ret = -1;
		goto out;
	}
	g_driver.support_dtype = true;
	if(!g_driver.overlay_opts->skip_mount_home) {
		if(ensure_mounted_as(driver_home, MS_PRIVATE, NULL) != 0) {
			ret = -1;
			goto out;
		}

	}

	if(umount2(driver_home, MNT_DETACH) && errno != EINVAL) {
		LOG_ERROR("Failed to umount the target : %s\n", driver_home);
		ret = -1;
		goto out;
	}

	if(driver_init_quota(&g_driver) != 0) {
		ret = -1;
		goto out;
	}
out:
	free(root_dir);
	return ret;
}

static int append_default_quota_opts(struct driver_create_opts *ori_opts, uint64_t quota) {
    int ret = 0; 
    int nret = 0; 
    size_t i = 0; 
    char tmp[50] = { 0 }; //tmp to hold unit64

    if (quota == 0) { 
        return 0;
    }    

    nret = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)quota);
    if (nret < 0 || (size_t)nret >= sizeof(tmp)) {
       	LOG_ERROR("Failed to make quota string");
        ret = -1;
        goto out; 
    }    

    if (ori_opts->storage_opt == NULL) {
        ori_opts->storage_opt = calloc_s(1, sizeof(json_map_string_string));
        if (ori_opts->storage_opt == NULL) {
        	LOG_ERROR("Memory out");
            ret = -1;
            goto out; 
        }
    }    

    for (i = 0; i < ori_opts->storage_opt->len; i++) {
        if (strcasecmp("size", ori_opts->storage_opt->keys[i]) == 0) { 
            break;
        }
    }    
    if (i == ori_opts->storage_opt->len) {
        ret = append_json_map_string_string(ori_opts->storage_opt, "size", tmp);
        if (ret != 0) { 
        	LOG_ERROR("Failed to append quota size option");
            ret = -1;
            goto out; 
        }
    }    

out:
    return ret; 
}

static int check_parent_valid(const char *parent, const struct graphdriver *driver) {
	int ret = 0;
	char *parent_dir = NULL;

	if(parent != NULL) {
		parent_dir = path_join(driver->home, parent);
		if(parent_dir == NULL) {
			LOG_ERROR("Failed to join layer dir: %s\n", parent);
			ret = -1;
			goto out;
		}
		if(!dir_exists(parent_dir)) {
			LOG_ERROR("parent layer %s not exists\n", parent_dir);
			ret = -1;
			goto out;
		}
	}
out:
	free(parent_dir);
	return ret;
}

static int set_layer_quota(const char *dir, const json_map_string_string *opts, const struct graphdriver *driver) {
	int ret = 0;
	size_t i = 0;
	uint64_t quota = 0;
	for(i = 0; i < opts->len; i++) {
		if(strcasecmp("size", opts->keys[i]) == 0) {
			int64_t converted = 0;
			ret = parse_byte_size_string(opts->values[i], &converted);
			if(ret != 0) {
				LOG_ERROR("Invalid size '%s' : %s\n", opts->values[i], strerror(-ret));
				ret = -1;
				goto out;
			}
			quota = (uint64_t)converted;
			break;
		} else {
			LOG_ERROR("Unknown option %s\n", opts->keys[i]);
			ret = -1;
			goto out;
		}
	}

	if(quota > 0 && quota < 4096) {
		LOG_ERROR("Illegal storage quota size %lu, 4096 at least\n", quota);
		ret = -1;
		goto out;
	}

	if(quota == 0) {
		quota = driver->overlay_opts->default_quota;
	}

	if(quota > 0) {
		ret = driver->quota_ctrl->set_quota(dir, driver->quota_ctrl,  quota);
	}
out:
	return ret;
}

static int do_diff_symlink(const char *id, char *link_id, const char *_driver_home) {
    int ret = 0;
    int nret = 0;
    char target_path[PATH_MAX] = { 0 };
    char link_path[PATH_MAX] = { 0 };
    char cleaned_path[PATH_MAX] = { 0 };

    nret = snprintf(target_path, PATH_MAX, "../%s/diff", id);
    if (nret < 0 || nret >= PATH_MAX) {
    	LOG_ERROR("Failed to get target path %s\n", id);
        ret = -1;
        goto out;
    }

    nret = snprintf(link_path, PATH_MAX, "%s/%s/%s", _driver_home, OVERLAY_LINK_DIR, link_id);
    if (nret < 0 || nret >= PATH_MAX) {
    	LOG_ERROR("Failed to get link path %s\n", link_id);
        ret = -1;
        goto out;
    }

    if (clean_path(link_path, cleaned_path, sizeof(cleaned_path)) == NULL) {
    	LOG_ERROR("failed to get clean path %s\n", link_path);
        ret = -1;
        goto out;
    }

    nret = symlink(target_path, cleaned_path);
    if (nret < 0) {
    	LOG_ERROR("Failed to create symlink from \"%s\" to \"%s\"\n", cleaned_path, target_path);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int mk_diff_symlink(const char *id, const char *layer_dir, const char *_driver_home)
{
    int ret = 0;
    char layer_id[MAX_LAYER_ID_LENGTH + 1] = { 0 };
    char *link_file = NULL;

    ret = generate_random_str(layer_id, MAX_LAYER_ID_LENGTH);
    if (ret != 0) {
    	LOG_ERROR("Failed to get layer symlink id %s\n", id);
        ret = -1;
        goto out;
    }

    ret = do_diff_symlink(id, layer_id, _driver_home);
    if (ret != 0) {
    	LOG_ERROR("Failed to do symlink id %s\n", id);
        ret = -1;
        goto out;
    }

    link_file = path_join(layer_dir, OVERLAY_LAYER_LINK);
    if (link_file == NULL) {
    	LOG_ERROR("Failed to get layer link file %s\n", layer_dir);
        ret = -1;
        goto out;
    }

    ret = write_file(link_file, layer_id, strlen(layer_id), 0666);
    if (ret) {
    	LOG_ERROR("Failed to write %s\n", link_file);
        ret = -1;
        goto out;
    }

out:
    free(link_file);
    return ret;
}

static int mk_diff_directory(const char *layer_dir) {
	int ret = 0;
	char *diff_dir = NULL;

	diff_dir = path_join(layer_dir, OVERLAY_LAYER_DIFF);
	if(diff_dir == NULL) {
		LOG_ERROR("Failed to join layer diff dir : %s\n", layer_dir);
		ret = -1;
		goto out;
	}

	if(mkdir_p(diff_dir, 0644) != 0) {
		LOG_ERROR("Unable to create layer diff directory %s\n", diff_dir);
		ret = -1;
		goto out;
	}

out:
	free(diff_dir);
	return ret;
}

static int mk_work_directory(const char *layer_dir) {
	int ret = 0;
	char *work_dir = NULL;

	work_dir = path_join(layer_dir, OVERLAY_LAYER_WORK);
	if(work_dir == NULL) {
		LOG_ERROR("Failed to join layer diff dir : %s\n", layer_dir);
		ret = -1;
		goto out;
	}

	if(mkdir_p(work_dir, 0644) != 0) {
		LOG_ERROR("Unable to create layer work directory %s\n", work_dir);
		ret = -1;
		goto out;
	}

out:
	free(work_dir);
	return ret;
}

static int mk_merged_directory(const char *layer_dir) {
	int ret = 0;
	char *merged_dir = NULL;

	merged_dir = path_join(layer_dir, OVERLAY_LAYER_MERGED);
	if(merged_dir == NULL) {
		LOG_ERROR("Failed to join layer diff dir : %s\n", layer_dir);
		ret = -1;
		goto out;
	}

	if(mkdir_p(merged_dir, 0644) != 0) {
		LOG_ERROR("Unable to create layer merged directory %s\n", merged_dir);
		ret = -1;
		goto out;
	}

out:
	free(merged_dir);
	return ret;
}

static int mk_empty_directory(const char *layer_dir) {
	int ret = 0;
	char *empty_dir = NULL;

	empty_dir = path_join(layer_dir, OVERLAY_LAYER_EMPTY);
	if(empty_dir == NULL) {
		LOG_ERROR("Failed to join layer diff dir : %s\n", layer_dir);
		ret = -1;
		goto out;
	}

	if(mkdir_p(empty_dir, 0766) != 0) {
		LOG_ERROR("Unable to create layer empty directory %s\n", empty_dir);
		ret = -1;
		goto out;
	}

out:
	free(empty_dir);
	return ret;
}

static char *get_lower(const char *parent, const char *_driver_home)
{
    int nret = 0;
    char *lower = NULL;
    size_t lower_len = 0;
    char *parent_dir = NULL;
    char *parent_link_file = NULL;
    char *parent_link = NULL;
    char *parent_lower_file = NULL;
    char *parent_lowers = NULL;

    parent_dir = path_join(_driver_home, parent);
    if (parent_dir == NULL) {
    	LOG_ERROR("Failed to get parent dir %s\n", parent);
        goto out;
    }

    parent_link_file = path_join(parent_dir, OVERLAY_LAYER_LINK);
    if (parent_link_file == NULL) {
    	LOG_ERROR("Failed to get parent link %s\n", parent_dir);
        goto out;
    }

    parent_link = read_text_file(parent_link_file);
    if (parent_link == NULL) {
    	LOG_ERROR("Failed to read parent link %s\n", parent_link_file);
        goto out;
    }

    if (strlen(parent_link) >= (INT_MAX - strlen(OVERLAY_LINK_DIR) - 2)) {
    	LOG_ERROR("parent link %s too large\n", parent_link_file);
        goto out;
    }

    lower_len = strlen(OVERLAY_LINK_DIR) + 1 + strlen(parent_link) + 1;

    parent_lower_file = path_join(parent_dir, OVERLAY_LAYER_LOWER);
    if (parent_lower_file == NULL) {
    	LOG_ERROR("Failed to get parent lower %s\n", parent_dir);
        goto out;
    }

    parent_lowers = read_text_file(parent_lower_file);
    if (parent_lowers != NULL) {
        if (strlen(parent_lowers) >= (INT_MAX - lower_len - 1)) {
        	LOG_ERROR("parent lower %s too large\n", parent_link_file);
            goto out;
        }
        lower_len = lower_len + strlen(parent_lowers) + 1;
    }

    lower = calloc_s(1, lower_len);
    if (lower == NULL) {
    	LOG_ERROR("Memory out\n");
        goto err_out;
    }

    if (parent_lowers != NULL) {
        nret = snprintf(lower, lower_len, "%s/%s:%s", OVERLAY_LINK_DIR, parent_link, parent_lowers);
    } else {
        nret = snprintf(lower, lower_len, "%s/%s", OVERLAY_LINK_DIR, parent_link);
    }
    if (nret < 0 || nret >= lower_len) {
    	LOG_ERROR("lower %s too large\n", parent_link);
        goto err_out;
    }

    /*if (check_lower_depth(lower) != 0) {
        goto err_out;
    }*/

    goto out;

err_out:
    free(lower);
    lower = NULL;

out:
    free(parent_dir);
    free(parent_link_file);
    free(parent_link);
    free(parent_lower_file);
    free(parent_lowers);
    return lower;
}

static int write_lowers(const char *layer_dir, const char *lowers)
{
    int ret = 0;
    char *lowers_file = NULL;

    lowers_file = path_join(layer_dir, OVERLAY_LAYER_LOWER);
    if (lowers_file == NULL) {
    	LOG_ERROR("Failed to get layer lower file %s\n", layer_dir);
        ret = -1;
        goto out;
    }

    ret = write_file(lowers_file, lowers, strlen(lowers), 0666);
    if (ret) {
    	LOG_ERROR("Failed to write %s\n", lowers_file);
        ret = -1;
        goto out;
    }

out:
    free(lowers_file);
    return ret;
}

static int mk_sub_directories(const char *id, const char *parent, const char *layer_dir, const char *_driver_home)
{
    int ret = 0; 
    char *lowers = NULL;

    if (mk_diff_directory(layer_dir) != 0) { 
        ret = -1;
        goto out; 
    }    

    if (mk_diff_symlink(id, layer_dir, _driver_home) != 0) { 
        ret = -1;
        goto out; 
    }    

    if (mk_work_directory(layer_dir) != 0) { 
        ret = -1;
        goto out; 
    }    

    if (mk_merged_directory(layer_dir) != 0) { 
        ret = -1;
        goto out; 
    }    

    if (parent == NULL) {
        if (mk_empty_directory(layer_dir) != 0) { 
            ret = -1;
            goto out; 
        }
    } else {
        lowers = get_lower(parent, _driver_home);
        if (lowers == NULL) {
            ret = -1;
            goto out; 
        }
        if (write_lowers(layer_dir, lowers) != 0) { 
            ret = -1;
            goto out; 
        }
    }    

out:
    free(lowers);
    return ret; 
}

static int do_create(const char *id, const char *parent, const struct graphdriver *driver, const struct driver_create_opts *create_opts) {
	int ret = 0;
	char *layer_dir = NULL;

	layer_dir = path_join(driver->home, id);
	if(layer_dir == NULL) {
		LOG_ERROR("Failed to join layer dir: %s", id);
		ret = -1;
		goto out;
	}

	if(check_parent_valid(parent, driver) != 0) {
		ret = -1;
		goto out;
	}

	if(mkdir_p(layer_dir, 0777) != 0) {
		LOG_ERROR("Unable to create layer directory %s.", layer_dir);
		ret = -1;
		goto out;
	}

	if(create_opts->storage_opt != NULL && create_opts->storage_opt->len != 0) {
		if(set_layer_quota(layer_dir, create_opts->storage_opt, driver) != 0) {
			LOG_ERROR("Unable to set layer quota %s", layer_dir);
			ret = -1;
			goto err_out;
		}
	}

	if(mk_sub_directories(id, parent, layer_dir, driver->home) != 0) {
		ret = -1;
		goto err_out;
	}

	goto out;

err_out:
	if(recursive_rmdir(layer_dir, 0)) {
		LOG_ERROR("Failed to delete layer path: %s", layer_dir);
	}
out:
	free(layer_dir);
	return ret;
}

int graphdriver_create_rw(const char *id, const char *parent, struct driver_create_opts *create_opts) {
	int ret = 0;

	if(id == NULL || create_opts == NULL) {
		LOG_ERROR("Invalid input arguments for driver create!\n");
		return -1;
	}
	
	if(create_opts->storage_opt != NULL && create_opts->storage_opt->len != 0 && !g_driver.support_quota) {
		LOG_ERROR("--storage-opt is support only for overlay over xfs or ext4\n");
		ret = -1;
		goto out;
	}
	
	if(g_driver.support_quota && append_default_quota_opts(create_opts, g_driver.overlay_opts->default_quota) != 0) {
		ret = -1;
		goto out;
	}

	ret = do_create(id, parent, &g_driver, create_opts);
out:
	return ret;
}

int graphdriver_create_ro(const char *id, const char *parent, const struct driver_create_opts *create_opts) {
	int ret = 0;

	if(id == NULL || create_opts == NULL) {
		LOG_ERROR("Invalid input arguments for driver create\n");
		return -1;
	}

	if(create_opts->storage_opt != NULL && create_opts->storage_opt->len != 0) {
		LOG_ERROR("--storage-opt size is only supported for ReadWrite Layers\n");
		return -1;
	}
	
	ret = do_create(id, parent, &g_driver, create_opts);
	return ret;
}

static int append_abs_empty_path(const char *layer_dir, char ***abs_lowers)
{
    int ret = 0;
    char *abs_path = NULL;

    abs_path = path_join(layer_dir, OVERLAY_LAYER_EMPTY);
    if (!dir_exists(abs_path)) {
    	LOG_ERROR("Can't stat absolute layer:%s\n", abs_path);
        ret = -1;
        goto out;
    }
    if (array_append(abs_lowers, abs_path) != 0) {
    	LOG_ERROR("Can't append absolute layer:%s\n", abs_path);
        ret = -1;
        goto out;
    }

out:
    free(abs_path);
    return ret;
}

static int append_rel_empty_path(const char *id, char ***rel_lowers)
{
    int ret = 0;
    char *rel_path = NULL;

    rel_path = string_append("/empty", id);

    if (array_append(rel_lowers, rel_path) != 0) {
    	LOG_ERROR("Can't append relative layer:%s\n", rel_path);
        ret = -1;
        goto out;
    }

out:
    free(rel_path);
    return ret;
}

static int get_mount_opt_lower_dir(const char *id, const char *layer_dir, const char *_driver_home, char **abs_lower_dir,
                                   char **rel_lower_dir)
{
    int ret = 0;
    char *lowers_str = NULL;
    char **lowers = NULL;
    char **abs_lowers = NULL;
    char **rel_lowers = NULL;
    size_t lowers_size = 0;
	int nlen = 0;
    size_t i = 0;

    lowers_str = read_layer_lower_file(layer_dir);
    lowers = string_split(lowers_str, ':', &nlen);
    lowers_size = nlen;//array_len((const char **)lowers);

    for (i = 0; i < lowers_size; i++) {
        if (append_abs_lower_path(_driver_home, lowers[i], &abs_lowers) != 0) {
            ret = -1;
            goto out;
        }

        if (array_append(&rel_lowers, lowers[i]) != 0) {
        	LOG_ERROR("Can't append relative layer:%s\n", lowers[i]);
            ret = -1;
            goto out;
        }
    }
    // If the lowers list is still empty, use an empty lower
    if (array_len((const char **)abs_lowers) == 0) {
        if (append_abs_empty_path(layer_dir, &abs_lowers) != 0) {
            ret = -1;
            goto out;
        }
        if (append_rel_empty_path(id, &rel_lowers) != 0) {
            ret = -1;
            goto out;
        }
    }
    *abs_lower_dir = string_join(":", (const char **)abs_lowers, array_len((const char **)abs_lowers));
    *rel_lower_dir = string_join(":", (const char **)rel_lowers, array_len((const char **)rel_lowers));
    if ((*abs_lower_dir) == NULL || (*rel_lower_dir) == NULL) {
    	LOG_ERROR("memory out\n");
        free(*abs_lower_dir);
        *abs_lower_dir = NULL;
        free(*rel_lower_dir);
        *rel_lower_dir = NULL;
        ret = -1;
        goto out;
    }
out:
    free(lowers_str);
    free_array_by_len(lowers, nlen);
    free_array(abs_lowers);
    free_array(rel_lowers);

    return ret;
}

static char *get_mount_opt_data_with_custom_option(size_t cur_size, const char *cur_opts,
                                                   const struct driver_mount_opts *mount_opts)
{
    int nret = 0;
    char *mount_data = NULL;
    char *custom_opts = NULL;
    size_t data_size = 0;

    custom_opts = string_join(",", (const char **)(mount_opts->options), mount_opts->options_len);
    if (custom_opts == NULL) {
    	LOG_ERROR("Failed to get custom mount opts\n");
        goto error_out;
    }

    if (strlen(custom_opts) >= (INT_MAX - cur_size - 1)) {
    	LOG_ERROR("custom mount option too large\n");
        goto error_out;
    }

    data_size = cur_size + strlen(custom_opts) + 1;
    mount_data = common_calloc_s(data_size);
    if (mount_data == NULL) {
    	LOG_ERROR("Memory out\n");
        goto error_out;
    }

    nret = snprintf(mount_data, data_size, "%s,%s", custom_opts, cur_opts);
    if (nret < 0 || (size_t)nret >= data_size) {
    	LOG_ERROR("Failed to get custom opts data\n");
        goto error_out;
    }

    goto out;

error_out:
    free(mount_data);
    mount_data = NULL;

out:
    free(custom_opts);
    return mount_data;
}

static char *get_mount_opt_data_with_driver_option(size_t cur_size, const char *cur_opts, const char *mount_opts)
{
    int nret = 0;
    char *mount_data = NULL;
    size_t data_size = 0;

    if (strlen(mount_opts) >= (INT_MAX - cur_size - 1)) {
    	LOG_ERROR("driver mount option too large\n");
        goto error_out;
    }

    data_size = cur_size + strlen(mount_opts) + 1;
    mount_data = common_calloc_s(data_size);
    if (mount_data == NULL) {
    	LOG_ERROR("Memory out\n");
        goto error_out;
    }

    nret = snprintf(mount_data, data_size, "%s,%s", mount_opts, cur_opts);
    if (nret < 0 || (size_t)nret >= data_size) {
    	LOG_ERROR("Failed to get driver opts data\n");
        goto error_out;
    }

    goto out;

error_out:
    free(mount_data);
    mount_data = NULL;

out:
    return mount_data;
}

static char *get_abs_mount_opt_data(const char *layer_dir, const char *abs_lower_dir, const struct graphdriver *driver,
                                    const struct driver_mount_opts *mount_opts)
{
    int nret = 0; 
    char *mount_data = NULL;
    size_t data_size = 0; 
    char *upper_dir = NULL;
    char *work_dir = NULL;
    char *tmp = NULL;

    upper_dir = path_join(layer_dir, OVERLAY_LAYER_DIFF);
    if (upper_dir == NULL) {
    	LOG_ERROR("Failed to join layer diff dir:%s\n", layer_dir);
        goto error_out;
    }    

    work_dir = path_join(layer_dir, OVERLAY_LAYER_WORK);
    if (work_dir == NULL) {
    	LOG_ERROR("Failed to join layer work dir:%s\n", layer_dir);
        goto error_out;
    }    

    if (strlen(abs_lower_dir) >= (INT_MAX - strlen("lowerdir=") - strlen(",upperdir=") - strlen(upper_dir) -
                                  strlen(",workdir=") - strlen(work_dir) - 1)) {
    	LOG_ERROR("abs lower dir too large\n");
        goto error_out;
    }    
    data_size = strlen("lowerdir=") + strlen(abs_lower_dir) + strlen(",upperdir=") + strlen(upper_dir) +
                strlen(",workdir=") + strlen(work_dir) + 1; 

    mount_data = common_calloc_s(data_size);
    if (mount_data == NULL) {
    	LOG_ERROR("Memory out\n");
        goto error_out;
    }    

    nret = snprintf(mount_data, data_size, "lowerdir=%s,upperdir=%s,workdir=%s", abs_lower_dir, upper_dir, work_dir);
    if (nret < 0 || (size_t)nret >= data_size) {
    	LOG_ERROR("abs lower dir too large\n");
        goto error_out;
    }    

    if (mount_opts != NULL && mount_opts->options_len != 0) { 
        tmp = get_mount_opt_data_with_custom_option(data_size, mount_data, mount_opts);
        if (tmp == NULL) {
            goto error_out;
        }
        free(mount_data);
        mount_data = tmp;
        tmp = NULL;
    } else if (driver->overlay_opts->mount_options != NULL) {
        tmp = get_mount_opt_data_with_driver_option(data_size, mount_data, driver->overlay_opts->mount_options);
        if (tmp == NULL) {
            goto error_out;
        }
        free(mount_data);
        mount_data = tmp;
        tmp = NULL;
    }

/*#ifdef ENABLE_SELINUX
    if (mount_opts != NULL && mount_opts->mount_label != NULL) {
        tmp = selinux_format_mountlabel(mount_data, mount_opts->mount_label);
        if (tmp == NULL) {
            goto error_out;
        }
        free(mount_data);
        mount_data = tmp;
        tmp = NULL;
    }
#endif*/

    goto out;

error_out:
    free(mount_data);
    mount_data = NULL;

out:
    free(upper_dir);
    free(work_dir);
    return mount_data;
}

static char *generate_mount_opt_data(const char *id, const char *layer_dir, const struct graphdriver *driver,
                                     const struct driver_mount_opts *mount_opts, bool *use_rel_mount)
{
    int ret = 0;
    char *mount_data = NULL;
    char *abs_lower_dir = NULL;
    char *rel_lower_dir = NULL;
    int page_size = 2048;//getpagesize();

    ret = get_mount_opt_lower_dir(id, layer_dir, driver->home, &abs_lower_dir, &rel_lower_dir);
    if (ret != 0) {
    	LOG_ERROR("Failed to get mount opt lower dir\n");
        goto out;
    }

    mount_data = get_abs_mount_opt_data(layer_dir, abs_lower_dir, driver, mount_opts);
    if (mount_data == NULL) {
    	LOG_ERROR("Failed to get abs mount opt data");
        goto out;
    }
    /*if (strlen(mount_data) > page_size) {
        free(mount_data);
        *use_rel_mount = true;
        mount_data = get_rel_mount_opt_data(id, rel_lower_dir, driver, mount_opts);
        if (mount_data == NULL) {
            ERROR("Failed to get abs mount opt data");
            goto out;
        }
        if (strlen(mount_data) > page_size) {
            ERROR("cannot mount layer, mount label too large %s", mount_data);
            free(mount_data);
            mount_data = NULL;
            goto out;
        }
    }*/

out:
    free(abs_lower_dir);
    free(rel_lower_dir);
    return mount_data;
}

static int abs_mount(const char *layer_dir, const char *merged_dir, const char *mount_data)
{
    int ret = 0;

    ret = util_mount("overlay", merged_dir, "overlay", 0, mount_data);
    if (ret != 0) {
    	LOG_ERROR("Failed to mount %s with option \"%s\"\n", merged_dir, mount_data);
        goto out;
    }

out:
    return ret;
}

/*static int rel_mount(const char *driver_home, const char *id, const char *mount_data)
{
    int ret = 0;
    char *mount_target = NULL;

    mount_target = string_append("/merged", id);
    if (mount_target == NULL) {
    	LOG_ERROR("Failed to join layer merged dir:%s\n", id);
        ret = -1;
        goto out;
    }

    ret = mount_from(driver_home, "overlay", mount_target, "overlay", mount_data);
    if (ret != 0) {
        ERROR("Failed to mount %s with option \"%s\"", mount_target, mount_data);
        ret = -1;
        goto out;
    }

out:
    free(mount_target);
    return ret;
}*/

static char *do_mount_layer(const char *id, const char *layer_dir, const struct graphdriver *driver,
                            const struct driver_mount_opts *mount_opts)
{
    char *merged_dir = NULL;
    char *mount_data = NULL;
    bool use_rel_mount = false;
    
	mount_data = generate_mount_opt_data(id, layer_dir, driver, mount_opts, &use_rel_mount);
    if (mount_data == NULL) {
    	LOG_ERROR("Failed to get mount data\n");
        goto error_out;
    }

    merged_dir = path_join(layer_dir, OVERLAY_LAYER_MERGED);
    if (merged_dir == NULL) {
    	LOG_ERROR("Failed to join layer merged dir:%s\n", layer_dir);
        goto error_out;
    }

	if(!dir_exists(merged_dir) && mkdir_p(merged_dir, 0666) != 0) {
		goto error_out;
	}

    if (!use_rel_mount) {
        if (abs_mount(layer_dir, merged_dir, mount_data) != 0) {
        	LOG_ERROR("Failed to mount %s with option \"%s\"\n", merged_dir, mount_data);
            goto error_out;
        }
    } else {
        /*if (rel_mount(driver->home, id, mount_data) != 0) {
        	LOG_ERROR("Failed to mount %s from %s with option \"%s\"\n", id, driver->home, mount_data);
            goto error_out;
        }*/
    }

    goto out;

error_out:
    free(merged_dir);
    merged_dir = NULL;

out:
    free(mount_data);
    return merged_dir;
}

char *overlay2_mount_layer(const char *id, const struct graphdriver *driver, const struct driver_mount_opts *mount_opts)
{
    char *merged_dir = NULL;
    char *layer_dir = NULL;

    if (id == NULL || driver == NULL) {
    	LOG_ERROR("Invalid input arguments");
        return NULL;
    }    
    layer_dir = path_join(driver->home, id); 
    if (layer_dir == NULL) {
    	LOG_ERROR("Failed to join layer dir:%s\n", id); 
        goto out; 
    }    
    if (!dir_exists(layer_dir)) {
    	LOG_ERROR("layer dir %s not exist\n", layer_dir);
        goto out; 
    }    

    merged_dir = do_mount_layer(id, layer_dir, driver, mount_opts);
    if (merged_dir == NULL) {
    	LOG_ERROR("Failed to mount layer %s\n", id); 
        goto out; 
    }    
out:
    free(layer_dir);
    return merged_dir;
}

char *graphdriver_mount_layer(const char *id, const struct driver_mount_opts *mount_opts)
{
    char *result = NULL;

    if (id == NULL) {
    	LOG_ERROR("Invalid input arguments for driver mount layer\n");
        return NULL;
    }

    result = g_driver.ops->mount_layer(id, &g_driver, mount_opts);


    return result;
}

int overlay2_umount_layer(const char *id, const struct graphdriver *driver) {
	int ret = 0;
	char *merged_dir = NULL;
	char *layer_dir = NULL;

	if(id == NULL || driver == NULL) {
		LOG_ERROR("Invalid input arguments");
		return -1;
	}

	layer_dir = path_join(driver->home, id);
	if(layer_dir == NULL) {
		LOG_ERROR("Failed to join layer dir : %s", id);
		ret = -1;
		goto out;
	}
	
	if(!dir_exists(layer_dir)) {
		LOG_ERROR("layer dir %s not exist", layer_dir);
		goto out;
	}
	
	merged_dir = path_join(layer_dir, OVERLAY_LAYER_MERGED);
	if(merged_dir == NULL) {
		LOG_ERROR("Failed to join layer merged dir : %s", layer_dir);
		ret = -1;
		goto out;
	}
	
	if(dir_exists(merged_dir) && umount2(merged_dir, MNT_DETACH) && errno != EINVAL) {
		LOG_ERROR("Failed to umount the target : %s for %s", merged_dir, strerror(errno));
	}
out:
	free(layer_dir);
	free(merged_dir);
	return ret;
}

int graphdriver_umount_layer(const char *id)
{
    int ret = 0;

    if (id == NULL) {
    	LOG_ERROR("Invalid input arguments for driver mount layer");
        return 0;
    }

    ret = g_driver.ops->umount_layer(id, &g_driver);

    return ret;
}

void free_graphdriver_mount_opts(struct driver_mount_opts *opts) {
	if(opts == NULL) {
		return;
	}

	if(opts->mount_label != NULL) {
		free(opts->mount_label);
	}
	free_array_by_len(opts->options, opts->options_len);
	free(opts);
	return;
}

int overlay2_rm_layer(const char *id, const struct graphdriver *driver)
{
    int ret = 0;
    int nret = 0;
    char *layer_dir = NULL;
    char *link_id = NULL;
    char link_path[PATH_MAX] = { 0 };
    char clean_path[PATH_MAX] = { 0 };

    if (id == NULL || driver == NULL) {
    	LOG_ERROR("Invalid input arguments");
        return -1;
    }

    layer_dir = path_join(driver->home, id);
    if (layer_dir == NULL) {
    	LOG_ERROR("Failed to join layer dir:%s", id);
        ret = -1;
        goto out;
    }
	if (recursive_rmdir(layer_dir, 0) != 0) {
    	LOG_ERROR("Failed to remove layer directory %s", layer_dir);
        ret = -1;
        goto out;
    }

out:
	free(layer_dir);
	free(link_id);
	return ret;
}

int graphdriver_rm_layer(const char *id) {
	int ret = 0;

	if(id == NULL) {
		LOG_ERROR("Invalid input arguments for driver remove layer");
		return -1;
	}

	ret = g_driver.ops->rm_layer(id, &g_driver);
	
	return ret;
}
