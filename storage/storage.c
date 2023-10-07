#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include "storage.h"
#include "sha256.h"
#include "fs.h"
#include "io_wrapper.h"
#include "registry_manifest_schema1.h"
#include "registry_manifest_schema2.h"
#include "oci_image_manifest.h"
#include "docker_image_config_v2.h"
#include "layer.h"
#include "rootfs.h"

struct image_list_elem {
	char* img_id;
	image_t* img;
	struct image_list_elem* next;
};

typedef struct image_store {
	char* dir;
	struct image_list_elem* image_list;
	size_t image_list_len;
} image_store_t;

image_store_t* g_image_store = NULL;

static int try_fill_image_spec(image_t* img, const char* id, const char* image_store_dir) {
	int ret = 0;
	int nret = 0;
	char* base_name = NULL;
	char* sha256_key = NULL;
	char config_file[PATH_MAX] = { 0 };
	parser_error err = NULL;
	if(img == NULL || id == NULL || image_store_dir == NULL)
		return -1;
	sha256_key = calc_full_digest(id);
	if(sha256_key == NULL) {
		printf("Failed to get sha256 key\n");
		return -1;
	}
	base_name = make_big_data_base_name(sha256_key);
	if(base_name == NULL) {
		printf("Failed to retrieve oci image spec file's base name\n'");
		ret = -1;
		goto out;
	}

	nret = sprintf(config_file, "%s/%s/%s", image_store_dir, id, base_name);
	if(nret < 0 || nret > PATH_MAX) {
		printf("Failed to retrieve oci image spac file\n");
		ret = -1;
		goto out;
	}
	img->spec = storage_spec_parse_file(config_file, NULL, &err);
	if(img->spec == NULL) {
		printf("Failed to parse oci image spec : %s\n", err != NULL ? (char*)err : " ");
		ret = -1;
		goto out;
	}
out:
	free(base_name);
	free(sha256_key);
	return ret;
}

static int save_image(storage_storage* img) {
	int ret = 0;
	char image_path[PATH_MAX] = { 0x00 };
	char image_dir[PATH_MAX] = { 0x00 };
	parser_error err = NULL;
	char* json_data = NULL;

	ret = snprintf(image_path, sizeof(image_path), "%s/%s/%s", storage_dir, img->id, IMAGE_JSON);
	if(ret < 0 || ret >= sizeof(image_path))  {
		printf("Failed to get image path by id : %s\n", img->id);
		return -1;
	}
	strcpy(image_dir, image_path);
	ret = mkdir_p(dirname(image_dir), 0700);
	if(ret < 0) {
		printf("Failed to create image directory %s.\n", image_path);
		return -1;
	}
	json_data = storage_storage_generate_json(img, NULL, &err);
	if(json_data == NULL) {
		printf("Failed to generate image json path string:%s\n", err ? err : " ");
		ret = -1;
	}
	if(write_file(image_path, json_data, strlen(json_data), 0600) != 0) {
		printf("Failed to save image json file\n");
		ret = -1;
		goto out;
	}
out:
	free(json_data);
	free(err);
	return ret;
}

int append_name(char*** names, size_t* names_len, const char* name) {
	size_t new_size, old_size;
	char** tmp_names = NULL;

	if(name == NULL) {
		return 0;
	}

	old_size = *names_len * sizeof(char*);
	new_size = old_size + sizeof(char*);

	if(mem_realloc((void**)&tmp_names, new_size, (void*)*names, old_size) != 0) {
		printf("Failed to realloc memory\n");
		return -1;
	}

	*names = tmp_names;
	(*names)[(*names_len)] = strdup_s(name);
	(*names_len)++;

	return 0;
}

static int append_image(const char* id, const char* searchable_digest, image_t* img) {
	int ret = 0;
	size_t i = 0;
	size_t record_name_len = 0;
	struct image_list_elem*	elem;
	
	elem = (struct image_list_elem*)malloc(sizeof(struct image_list_elem));
	elem->img_id = strdup_s(img->simage->id);
	elem->img = img;
	elem->next = g_image_store->image_list->next;
	g_image_store->image_list->next = elem;

	return 0;
}

image_t *delete_image(const char *id) {
	struct image_list_elem *elem = NULL, *c;

	elem = g_image_store->image_list;
	while(elem->next != NULL && strcmp(elem->next->img_id, id) != 0 && strcmp(elem->next->img->simage->names[0], id) != 0) {
		elem = elem->next;
	}
	if(elem->next == NULL) {
		printf("img %s not found\n", id);
		return NULL;
	}
	
	c = elem->next;
	elem->next = elem->next->next;
	image_t *img = c->img;
	free(c->img_id);
	free(c);
	return img;
}

static image_t* lookup(const char* img_id) {
	image_t* ret;
	int i = 0;
	int flag = 0;
	struct image_list_elem* elem;

	elem = g_image_store->image_list->next;
	while(elem != NULL && strcmp(elem->img_id, img_id) != 0 && strcmp(elem->img->simage->names[0], img_id) != 0) {
		elem = elem->next;
	}
	
	if(elem == NULL) {
		elem = g_image_store->image_list->next;
		while(elem != NULL) {
			for(i = 0; i < elem->img->simage->names_len; i++) {
				if(strcmp(elem->img->simage->names[i], img_id) == 0) {
					flag = 1;
					break;
				}	
			}
			if(flag) {
				break;
			}
			elem = elem->next;
		}
	}

	if(elem == NULL) {
		printf("img %s not found!\n", img_id);
		goto out;
	}

	return elem->img;
out:
	return NULL;
}

static bool image_store_exists(const char *img_id) {
	if(lookup(img_id) != NULL) {
		return true;
	}
	return false;
}

bool storage_image_exist(const char *name) {
	return image_store_exists(name);
}

static image_summary *get_summary(const char *img_id) {
	int ret = 0;
	image_t *img = NULL;
	image_summary *info = NULL;

	info = common_calloc_s(sizeof(image_summary));
	if(info == NULL) {
		printf("Out of memory\n");
		ret = -1;
		goto out;
	}
	
	img = lookup(img_id);
	if(img == NULL) {
		printf("Failed to get img\n");
		ret = -1;
		goto out;
	}

	info->id = strdup_s(img->simage->id);
    info->created = strdup_s(img->simage->created);
    info->loaded = strdup_s(img->simage->loaded);
    info->size = img->simage->size;
    info->top_layer = strdup_s(img->simage->layer);

out:
	if(ret != 0 && info != NULL) {
		free(info);
		info = NULL;
	}

	return info;
}

image_summary *storage_img_get_summary(const char *img_id) {
	char *normalized_name = NULL;
	image_summary *image_summary = NULL;

	if(img_id == NULL) {
		printf("Invalid argumentx for image get summary\n");
		return NULL;
	}

	if(image_store_exists(img_id)) {
		image_summary = get_summary(img_id);
	} else {
		normalized_name = oci_normalize_image_name(img_id);
		image_summary = get_summary(normalized_name);
	}

	free(normalized_name);
	return image_summary;
}

void free_image_summary(image_summary *summary) {
	if(summary == NULL) {
		return;
	}
	free(summary->id);
	free(summary->created);
	free(summary->loaded);
	free(summary->top_layer);
	return;
}

int storage_img_get_names(const char *image_name, char ***names, size_t *names_len) {
	image_t *img;

	if(image_name == NULL) {
		printf("invalid NULL pointer\n");
		return -1;
	}

	img = lookup(image_name);
	if(img == NULL) {
		return -1;
	}

	*names = str_array_dup((const char**)(img->simage->names), img->simage->names_len);
	*names_len = img->simage->names_len;
	
	return 0;
}

char *storage_img_get_image_id(const char *image_name) {
	image_t *img;

	if(image_name == NULL) {
		printf("invalid NULL pointer\n");
		return NULL;
	}

	img = lookup(image_name);
	if(img == NULL) {
		return NULL;
	}

	return strdup_s(img->simage->id);
}

int image_store_add_name(const char *id, const char *name) {
	int ret = 0;
	image_t* img = NULL;
	image_t* other_image = NULL;
	char** unique_names = NULL;
	size_t unique_names_len = 0;
	char** names = NULL;
	size_t names_len = 0;
	size_t i;

	if(id == NULL || name == NULL) {
		printf("Invalid input parameter : %s, %s\n", id, name);
		return -1;
	}

	if(g_image_store == NULL) {
		printf("Image store is not ready\n");
		return -1;
	}

	img = lookup(id);
	if(img == NULL) {
		ret = -1;
		goto out;
	}
	
	if(dup_array_of_strings((const char**)img->simage->names, img->simage->names_len, &names, &names_len) != 0) {
		printf("Out of memory\n");
		ret = -1;
		goto out;
	}

	if(append_name(&names, &names_len, name) != 0) {
		printf("Out of memory\n");
		ret = -1;
		goto out;
	}
	free_array_by_len(img->simage->names, img->simage->names_len);
	img->simage->names = names;
	img->simage->names_len = names_len;

	if(save_image(img->simage) != 0) {
		printf("Failed to update image\n");
		ret = -1;
		goto out;
	}

out:
	return ret;
}

static inline int get_data_dir(const char* id, char* path, size_t len) {
	int nret = snprintf(path, len, "%s/%s", storage_dir, id);
	return (nret < 0 || (size_t)nret >= len) ? -1 : 0;
}

static int get_data_path(const char* id, const char* key, char* path, size_t len) {
	int ret = 0;
	int nret = 0;
	char* data_base_name = NULL;
	char data_dir[PATH_MAX] = { 0x00 };

	data_base_name = make_big_data_base_name(key);
	if(data_base_name == NULL) {
		printf("Failed to make big data base name\n");
		return -1;
	}

	if(get_data_dir(id, data_dir, sizeof(data_dir)) != 0) {
		printf("Failed to get image data dir: %s\n", id);
		ret = -1;
		goto out;
	}

	nret = snprintf(path, len, "%s/%s", data_dir, data_base_name);
	if(nret < 0 || (size_t)nret >= len) {
		printf("Failed to get big data base path\n");
		ret = -1;
		goto out;
	}
out:
	free(data_base_name);
	return ret;
}

static void update_json_map_string_int64(json_map_string_int64* map, const char* key, int64_t value) {
	size_t i;
	for(int i = 0; i < map->len; i++) {
		if(strcmp(key, map->keys[i]) == 0) {
			map->values[i] = value;
			return;
		}
	}
}

static bool get_value_from_json_map_string_int64(json_map_string_int64 *map, const char *key, int64_t *value)
{
    size_t i;
    for (i = 0; i < map->len; i++) {
        if (strcmp(key, map->keys[i]) == 0) { 
            *value = map->values[i];
            return true;
        }
    }    
    return false;
}

static void update_json_map_string_string(json_map_string_string *map, const char *key, const char *value)
{
    size_t i;

    for (i = 0; i < map->len; i++) {
        if (strcmp(key, map->keys[i]) == 0) { 
            free(map->values[i]);
            map->values[i] = (void *)strdup_s(value);
        }    
    }    
}

static char *get_value_from_json_map_string_string(json_map_string_string *map, const char *key)
{
    size_t i;

    if (map == NULL) {
        return NULL;
    }    

    for (i = 0; i < map->len; i++) {
        if (strcmp(key, map->keys[i]) == 0) { 
            return strdup_s(map->values[i]);
        }
    }    

    return NULL;
}

static int append_big_data_name(storage_storage *im, const char *name)
{
    size_t new_size, old_size;
    char **tmp_names = NULL;

    if (name == NULL) {
        return 0;
    }

    old_size = im->big_data_names_len * sizeof(char *);
    new_size = old_size + sizeof(char *);

    if (mem_realloc((void **)&tmp_names, new_size, (void *)im->big_data_names, old_size) != 0) {
        printf("Failed to realloc memory");
        return -1;
    }

    im->big_data_names = tmp_names;
    im->big_data_names[im->big_data_names_len++] = strdup_s(name);

    return 0;
}

static int update_image_with_big_data(image_t *img, const char *key, const char *data, bool *should_save)
{
    int ret = 0; 
    bool size_found = false;
    int64_t old_size;
    char *old_digest = NULL;
    char *new_digest = NULL;
    char *full_digest = NULL;
    bool add_name = true;
    size_t i;
    //digest_image_t *digest_filter_images = NULL;

    if (img->simage->big_data_sizes == NULL) {
        img->simage->big_data_sizes = (json_map_string_int64 *)calloc_s(1, sizeof(json_map_string_int64));
        if (img->simage->big_data_sizes == NULL) {
            printf("Out of memory");
            return -1;
        }
    }    

    size_found = get_value_from_json_map_string_int64(img->simage->big_data_sizes, key, &old_size);
    if (size_found) {
        update_json_map_string_int64(img->simage->big_data_sizes, key, (int64_t)strlen(data));
    } else {
        append_json_map_string_int64(img->simage->big_data_sizes, key, (int64_t)strlen(data));
    }    

    if (img->simage->big_data_digests == NULL) {
        img->simage->big_data_digests = (json_map_string_string *)calloc_s(1, sizeof(json_map_string_string));
        if (img->simage->big_data_digests == NULL) {
            printf("Out of memory");
            return -1;
        }
    }    

    old_digest = get_value_from_json_map_string_string(img->simage->big_data_digests, key);
    new_digest = sha256_digest_str(data);
    full_digest = calc_full_digest(new_digest);
    if (old_digest != NULL) {
        update_json_map_string_string(img->simage->big_data_digests, key, full_digest);
    } else {
        append_json_map_string_string(img->simage->big_data_digests, key, full_digest);
    }

    if (!size_found || old_size != (int64_t)strlen(data) || old_digest == NULL ||
        strcmp(old_digest, full_digest) != 0) {
        *should_save = true;
    }

    for (i = 0; i < img->simage->big_data_names_len; i++) {
        if (strcmp(img->simage->big_data_names[i], key) == 0) {
            add_name = false;
            break;
        }
    }

    if (add_name) {
        if (append_big_data_name(img->simage, key) != 0) {
            printf("Failed to append big data name");
            ret = -1;
            goto out;
        }
        *should_save = true;
    }

    if (strcmp(key, IMAGE_DIGEST_BIG_DATA_KEY) == 0) {
        if (old_digest != NULL && strcmp(old_digest, full_digest) != 0 &&
            strcmp(old_digest, img->simage->digest) != 0) {
            /*if (remove_image_from_digest_index(img, old_digest) != 0) {
                printf("Failed to remove the image from the list of images in the digest-based "
                      "index which corresponds to the old digest for this item, unless it's also the hard-coded digest");
                ret = -1;
                goto out;
            }*/
        }
        // add the image to the list of images in the digest-based index which
        // corresponds to the new digest for this item, unless it's already there
        /*digest_filter_images = (digest_image_t *)map_search(g_image_store->bydigest, (void *)full_digest);
        if (digest_filter_images != NULL) {
            digest_image_slice_without_value(digest_filter_images, img);
            if (append_image_to_digest_images(digest_filter_images, img) != 0) {
                ERROR("Failed to append image to digest images");
                ret = -1;
                goto out;
            }
        }*/
    }

out:
    free(old_digest);
    free(new_digest);
    free(full_digest);
    return ret;
}

static int set_image_size(const char *id, uint64_t size)
{
    int ret = 0; 
    image_t *img = NULL;

    if (id == NULL) {
        printf("Invalid parameter, id is NULL\n");
        return -1;
    }    

    if (g_image_store == NULL) {
        printf("Image store is not ready\n");
        return -1;
    }    

    /*if (!image_store_lock(EXCLUSIVE)) {
        ERROR("Failed to lock image store with exclusive lock, not allowed to modify image size");
        return -1;
    }    */

    img = lookup(id);
    if (img == NULL) {
        printf("Image not known\n");
        ret = -1;
        goto out; 
    }    

    img->simage->size = size;
    if (save_image(img->simage) != 0) { 
        printf("Failed to save image\n");
        ret = -1;
        goto out; 
    }    

out:
    //image_ref_dec(img);
    //image_store_unlock();
    return ret; 
}

char *get_top_layer(const char *id)
{
    image_t *img = NULL;
    char *top_layer = NULL;

    if (id == NULL) {
        printf("Invalid parameter, id is NULL");
        return NULL;
    }

    if (g_image_store == NULL) {
        printf("Image store is not ready");
        return NULL;
    }

    /*if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image top layer assignments");
        return NULL;
    }*/

    img = lookup(id);
    if (img == NULL) {
        printf("Image not known");
        goto out;
    }

    top_layer = strdup_s(img->simage->layer);

out:
    //image_ref_dec(img);
    //image_store_unlock();
	img->refcnt -= 1;
    return top_layer;
}

static int get_big_data_names(const char *id, char ***names, size_t *names_len) {
	int ret = 0;
	image_t *img = NULL;
	if(id == NULL) {
		printf("Invalid parameter, id is NULL\n");
		return -1;
	}
	if(g_image_store == NULL) {
		printf("Image store is not ready\n");
		return -1;
	}
	img = lookup(id);
	if(img == NULL) {
		printf("Image not known\n");
		ret = -1;
		goto out;
	}
	if(dup_array_of_strings((const char**)img->simage->big_data_names, img->simage->big_data_names_len, names, names_len) != 0) {
		printf("Failed to dup images's names\n'");
		ret = -1;
		goto out;
	}
out:
	img->refcnt = 0;
	return ret;
}

static int set_big_data(const char* id, const char* key, const char* data) {
	int ret = 0;
	image_t* img;
	const char* image_id = NULL;
	char image_dir[PATH_MAX] = { 0x00 };
	char big_data_file[PATH_MAX] = { 0x00 };
	bool save = false;

	if(key == NULL || strlen(key) == 0) {
		printf("invalid empty key\n");
		return -1;
	}

	if(g_image_store == NULL) {
		printf("Image store is not ready\n");
		ret = -1;
		goto out;
	}

	img = lookup(id);
	//printf("%s\n", img->simage->names[0]);
	if(img == NULL) {
		printf("Failed to lookup image from store\n");
		ret = -1;
		goto out;
	}
	image_id = img->simage->id;

	if(get_data_dir(image_id, image_dir, sizeof(image_dir)) != 0) {
		printf("Failed to get image data dir: %s\n", id);
		ret = -1;
		goto out;
	}
	
	ret = mkdir_p(image_dir, 0600);
	
	if(ret < 0) {
		printf("Unable to create directory %s.\n", image_dir);
		ret = -1;
		goto out;
	}
	
	if(get_data_path(image_id, key,  big_data_file, sizeof(big_data_file)) != 0) {
		printf("Failed to get big data file path: %s\n", key);
		ret = -1;
		goto out;
	}
	
	if(write_file(big_data_file, data, strlen(data), 0600)) {
		printf("Failed to save big data file: %s\n", big_data_file);
		ret = -1;
		goto out;
	}
	if(update_image_with_big_data(img, key, data, &save) != 0) {
		printf("Failed to update image big data\n");
		ret = -1;
		goto out;
	}
	if(img->spec == NULL) {
		try_fill_image_spec(img, image_id, g_image_store->dir);
	}
	if(save && save_image(img->simage) != 0) {
		printf("Failed to complete persistence to disk\n");
		ret = -1;
		goto out;
	}
out:
	return ret;
}

static int get_size_with_update_big_data(const char *id, const char *key, int64_t *size)
{
    int ret = 0;
    image_t *img = NULL;
    char *data = NULL;

    data = image_store_big_data(id, key);
    if (data == NULL) {
        return -1;
    }

    if (set_big_data(id, key, data) != 0) {
        free(data);
        return -1;
    }

    free(data);

    /*if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image big data size assignments");
        return -1;
    }*/

    img = lookup(id);
    if (img == NULL) {
        printf("Image not known");
        ret = -1;
        goto out;
    }

    get_value_from_json_map_string_int64(img->simage->big_data_sizes, key, size);

out:
    //image_ref_dec(img);
    //image_store_unlock();
    img->refcnt -= 1;
	return ret;
}

static int64_t get_big_data_size(const char *id, const char *key)
{
    bool bret = false;
    image_t *img = NULL;
    int64_t size = -1;

    if (id == NULL) {
        printf("Invalid parameter, id is NULL\n");
        return -1;
    }    

    if (key == NULL || strlen(key) == 0) { 
        printf("Not a valid name for a big data item, can't retrieve image big data value for empty name\n");
        return -1;
    }    

    if (g_image_store == NULL) {
        printf("Image store is not ready\n");
        return -1;
    }    

    /*if (!image_store_lock(SHARED)) {
        ("Failed to lock image store with shared lock, not allowed to get image big data size assignments");
        return -1;
    }*/    

    img = lookup(id);
    if (img == NULL) {
        printf("Image not known");
        //image_store_unlock();
        goto out; 
    }    

    bret = get_value_from_json_map_string_int64(img->simage->big_data_sizes, key, &size);

    //image_ref_dec(img);
	img->refcnt -= 1;
    //image_store_unlock();

    if (bret || get_size_with_update_big_data(id, key, &size) == 0) { 
        goto out; 
    }    

    printf("Size is not known");

out:
    return size;
}

static int64_t storage_img_cal_image_size(const char *image_id)
{
    size_t i = 0;
    int64_t total_size = -1;
    char *layer_id = NULL;
    char **big_data_names = NULL;
    size_t big_data_len = 0;
    struct layer *layer_info = NULL;

    if (image_id == NULL) {
        printf("Invalid arguments\n");
        total_size = -1;
        goto out;
    }

    if (get_big_data_names(image_id, &big_data_names, &big_data_len) != 0) {
        printf("Failed to read image %s big datas\n", image_id);
        total_size = -1;
        goto out;
    }

    for (i = 0; i < big_data_len; i++) {
        int64_t tmp = get_big_data_size(image_id, big_data_names[i]);
        if (tmp == -1) {
            printf("Failed to read big data %s for image %s\n", big_data_names[i], image_id);
            total_size = -1;
            goto out;
        }
        total_size += tmp;
    }

    layer_id = get_top_layer(image_id);
    if (layer_id == NULL) {
        printf("Failed to get top layer of image %s\n", image_id);
        total_size = -1;
        goto out;
    }

    while (layer_id != NULL) {
        layer_info = layer_store_lookup(layer_id);
        if (layer_info == NULL) {
            printf("Failed to get layer info for layer %s\n", layer_id);
            total_size = -1;
            goto out;
        }

        if (layer_info->uncompress_size < 0 || layer_info->uncompressed_digest == NULL) {
            printf("size for layer %s unknown\n", layer_id);
            total_size = -1;
			goto out;
        }

        total_size += layer_info->uncompress_size;

        free(layer_id);
        layer_id = strdup_s(layer_info->parent);
        free_layer(layer_info);
        layer_info = NULL;
    }

out:
    free(layer_id);
    free_layer(layer_info);
    free_array_by_len(big_data_names, big_data_len);
    return total_size;
}

int storage_img_set_image_size(const char *image_id)
{
    int ret = 0; 
    int64_t image_size = 0; 

    image_size = storage_img_cal_image_size(image_id);
    if (image_size < 0) { 
        printf("Failed to get image %s size", image_id);
        ret = -1;
        goto out; 
    }    

    if (set_image_size(image_id, (uint64_t)image_size) != 0) { 
        printf("Failed to set image %s size %lu", image_id, (uint64_t)image_size);
        ret = -1;
        goto out; 
    }    

out:
    return ret; 
}

int storage_img_set_names(const char *img_id, const char **names, size_t names_len) {
	image_t *img;

	if(img_id == NULL) {
		printf("invalid NULL pointer\n");
		return -1;
	}

	img = lookup(img_id);
	if(img == NULL) {
		return -1;
	}
	free_array_by_len(img->simage->names, img->simage->names_len);
	img->simage->names = str_array_dup(names, names_len);
	img->simage->names_len = names_len;

	return 0;
}

static int set_load_time(const char *id, const types_timestamp_t *time)
{
    int ret = 0; 
    image_t *img = NULL;
    char timebuffer[TIME_STR_SIZE] = { 0x00 };

    if (id == NULL || time == NULL) {
        printf("Invalid input paratemers\n");
        return -1;
    }    

    if (g_image_store == NULL) {
        printf("Image store is not ready\n");
        return -1;
    }    

    /*if (!image_store_lock(EXCLUSIVE)) {
        printf("Failed to lock image store with exclusive lock, not allowed to modify image metadata\n");
        return -1;
    }    */

    img = lookup(id);
    if (img == NULL) {
        printf("image not known\n");
        ret = -1;
        goto out; 
    }    

    if (!get_time_buffer(time, timebuffer, sizeof(timebuffer), false)) {
        printf("Failed to get time buffer\n");
        ret = -1;
        goto out; 
    }    

    free(img->simage->loaded);
    img->simage->loaded = strdup_s(timebuffer);
    if (save_image(img->simage) != 0) { 
        printf("Failed to save image\n");
        ret = -1;
    }    

out:
    //image_ref_dec(img);
    //image_store_unlock();
    return ret; 
}

int storage_img_set_loaded_time(const char *img_id, types_timestamp_t *loaded_time)
{
    int ret = 0; 

    if (img_id == NULL || loaded_time == NULL) {
        printf("Invalid arguments\n");
        ret = -1;
        goto out; 
    }    

    if (set_load_time(img_id, loaded_time) != 0) { 
        printf("Failed to set img %s loaded time\n", img_id);
        ret = -1;
        goto out; 
    }    

out:
    return ret; 
}

int storage_img_set_big_data(const char *img_id, const char *key, const char *val) {
	int ret = 0;
	
	if(img_id == NULL || key == NULL || val == NULL) {
		printf("Invalid arguments\n");
		ret = -1;
		goto out;
	}

	if(set_big_data(img_id, key, val) != 0) {
		printf("Failed to set img %s big data %s=%s\n", img_id, key, val);
		ret = -1;
		goto out;
	}
out:
	return ret;
}

static int delete_img_related_layers(const char *img_id, const char *img_top_layer_id) {
	int ret = 0;
	char *layer_id = NULL;
	char *last_deleted_layer_id = NULL;
	struct layer *layer_info = NULL;

	layer_id = strdup_s(img_top_layer_id);
	if(layer_id == NULL) {
		printf("Memory out %s\n", img_id);
		ret = -1;
		goto out;
	}
		
	while(layer_id != NULL) {
		layer_info = layer_store_lookup(layer_id);
		
		if(layer_info == NULL) {
			printf("Failed to get layer info for layer %s\n", layer_id);
			ret = -1;
			goto out;
		}

		if(layer_store_delete(layer_id) != 0) {
			printf("Failed ro remove layer %s\n", layer_id);
			ret = -1;
			goto out;
		}

		free(last_deleted_layer_id);
	    last_deleted_layer_id = strdup_s(layer_id);
        free(layer_id);
        layer_id = strdup_s(layer_info->parent);
        free_layer(layer_info);
        layer_info = NULL;
	}

out:
	free(last_deleted_layer_id);
	free(layer_id);
	free_layer(layer_info);
	return ret;
}

static int check_image_occupancy_status(const char *img_id, bool *in_using) {
	bool ret = 0;
	size_t i;
	struct rootfs_list *all_rootfs = NULL;
	char *img_long_id = NULL;

	all_rootfs = common_calloc_s(sizeof(struct rootfs_list));
	if(all_rootfs == NULL) {
		printf("Out of known\n");
		ret = -1;
		goto out;
	}

	if(rootfs_store_get_all_rootfs(all_rootfs) != 0) {
		printf("Failed to get all container rootfs info\n");
		ret = -1;
		goto out;
	}

	for(i = 0; i < all_rootfs->rootfs_len; i++) {
		if(strcmp(all_rootfs->rootfs[i]->image, img_id) == 0) {
			printf("Image used by %s\n", all_rootfs->rootfs[i]->id);
			*in_using = true;
			goto out;
		}
	}
out:
	free_rootfs_list(all_rootfs);
	return ret;
}

int storage_img_delete(const char *img_id, bool commit) {
	int ret = 0;
	bool in_using = false;
	image_summary *summary = NULL;
	char img_path[PATH_MAX] = { 0 };
	image_t *img = NULL;

	if(img_id == NULL) {
		printf("Invalid input arguments\n");
		return -1;
	}

	if(!image_store_exists(img_id)) {
		printf("Image %s not exists\n", img_id);
		ret = 0;
		goto out;
	}

	summary = storage_img_get_summary(img_id);
	if(summary == NULL) {
		printf("Failed to get image %s summary\n", img_id);
		ret = -1;
		goto out;
	}
	
	if(check_image_occupancy_status(summary->id, &in_using) != 0) {
		printf("Failed ro check image occupancy status\n");
		ret = -1;
		goto out;
	}

	if(delete_img_related_layers(summary->id, summary->top_layer)) {
		printf("Failed to delete img related layer %s\n", img_id);
		ret = -1;
		goto out;
	}

	sprintf(img_path, "%s/%s", storage_dir, summary->id);
	ret = recursive_remove_path(img_path);
	if(ret < 0) {
		ret = -1;
		goto out;
	}

	img = delete_image(summary->id);
	if(img == NULL) {
		printf("Failed to delete img %s\n", img_id);
		ret = -1;
		goto out;
	}
	free_storage_storage(img->simage);
	free_storage_spec(img->spec);
	free(img);

out:
	free_image_summary(summary);
	return ret;	
}

int storage_img_create(const char *id, const char *parent_id, const char *metadata, struct storage_img_create_options *opts) {
	int ret = 0;
	char* image_id = NULL;
	char* dst_id = NULL;
	char** unique_names = NULL;
	size_t unique_names_len = 0;
	char* searchable_digest = opts->digest;
	char timebuffer[TIME_STR_SIZE] = { 0x00 };
	image_t* img = NULL;
	storage_storage* im = NULL;

	if(id == NULL || opts == NULL) {
		printf("invalid arguments for image create\n");
		ret = -1;
		goto out;
	}
	dst_id = strdup_s(id);
	if(dst_id == NULL) {
		printf("Out of memory\n");
		ret = -1;
		goto out;
	}
	im = (storage_storage*)calloc_s(1, sizeof(storage_storage));
	if(im == NULL) {
		printf("Failed to generate new storage image\n");
		ret = -1;
		goto out;
	}
	im->id = strdup_s(dst_id);
	im->digest = strdup_s(searchable_digest);
	im->names = unique_names;
	im->names_len = unique_names_len;
	im->layer = strdup_s(parent_id);
	im->metadata = strdup_s(metadata);
	get_now_time_buffer(timebuffer, sizeof(timebuffer));
	im->loaded = strdup_s(timebuffer);
	if(opts->create_time != NULL && (opts->create_time->has_seconds || opts->create_time->has_nanos) && !get_time_buffer(opts->create_time, timebuffer, sizeof(timebuffer), false)) {
		printf("Failed to get time buffer\n");
		ret = -1;
		goto out;
	}
	im->created = strdup_s(timebuffer);

	img = (image_t *)calloc_s(1, sizeof(image_t));
	img->refcnt = 1;
	try_fill_image_spec(img, im->id, storage_dir);
	img->simage = im;
	im = NULL;

	if(append_image(dst_id, searchable_digest, img) != 0) {
		printf("Failed to append image to image store!\n");
		ret = -1;
		goto out;
	}

	if(save_image(img->simage) != 0) {
		printf("failed to save image\n");
		ret = -1;
		goto out;
	}
	
	if(dst_id == NULL) {
		printf("Failed to create img\n");
		ret = -1;
		goto out;
	}
out:
	if(ret != 0) {
		free(dst_id);
		if(im != NULL)
			free_storage_storage(im);
		if(img != NULL) {
			if(img->spec != NULL) {
				free_storage_spec(img->spec);
			}
			free(img);
		}
	}
	else {
		img->refcnt = 0;
	}
	free_array_by_len(unique_names, unique_names_len);
	return ret;
}

char *image_store_big_data(const char *id, const char *key)
{
    int ret = 0;
    image_t *img = NULL;
    char filename[PATH_MAX] = { 0x00 };
    char *content = NULL;

    if (id == NULL) {
        printf("Invalid parameter, id is NULL");
        return NULL;
    }

    if (key == NULL || strlen(key) == 0) {
        printf("Not a valid name for a big data item, can't retrieve image big data value for empty name");
        return NULL;
    }

    if (g_image_store == NULL) {
        printf("Image store is not read");
        return NULL;
    }

    /*if (!image_store_lock(SHARED)) {
        ERROR("Failed to lock image store with shared lock, not allowed to get image big data");
        return NULL;
    }*/

    img = lookup(id);
    if (img == NULL) {
        printf("Image not known");
        goto out;
    }

    ret = get_data_path(img->simage->id, key, filename, sizeof(filename));

    if (ret != 0) {
        printf("Failed to get big data file path: %s.", key);
        goto out;
    }

    content = read_text_file(filename);

out:
    //image_ref_dec(img);
    //image_store_unlock();
    img->refcnt -= 1;
	return content;
}


static ssize_t layer_archive_io_read(void *context, void *buf, size_t buf_len) {
	int *read_fd = (int *)context;
	return read_nointr(*read_fd, buf, buf_len);
}

static int layer_archive_io_close(void *context, char **err) {
	int *read_fd = (int *)context;
	close(*read_fd);
	free(read_fd);
	return 0;
}

static int fill_read_wrapper(const char *layer_data_path, struct io_read_wrapper **reader) {
	int ret = 0;
	int *fd_ptr = NULL;
	struct io_read_wrapper *reader_tmp = NULL;
	if(layer_data_path == NULL) {
		return 0;
	}
	reader_tmp = calloc_s(sizeof(struct io_read_wrapper), 1);
	if(reader_tmp == NULL) {
		printf("Memory out\n");
		return -1;
	}

	fd_ptr = calloc_s(sizeof(int), 1);
	if(fd_ptr == NULL) {
		printf("Memory out\n");
		ret = -1;
		goto err_out;
	}
	char rpath[PATH_MAX] = { 0x00 };
	clean_path(layer_data_path, rpath, sizeof(rpath));
	*fd_ptr = open(layer_data_path, O_RDONLY | O_CLOEXEC);
	if(*fd_ptr == -1) {
		printf("Failed to open layer data %s\n", layer_data_path);
		ret = -1;
		goto err_out;
	}
	reader_tmp->context = fd_ptr;
	reader_tmp->read = layer_archive_io_read;
	reader_tmp->close = layer_archive_io_close;
	*reader = reader_tmp;

	fd_ptr = NULL;
	reader_tmp = NULL;

err_out:
	free(fd_ptr);
	free(reader_tmp);
	return ret;
}

static struct layer_opts *fill_create_layer_opts(storage_layer_create_opts_t *copts, const char *mount_label)
{
    struct layer_opts *opts = NULL;

    opts = calloc_s(1, sizeof(struct layer_opts));
    if (opts == NULL) {
        printf("Memory out");
        goto out; 
    }    

    opts->parent = strdup_s(copts->parent);
    opts->uncompressed_digest = strdup_s(copts->uncompress_digest);
    opts->compressed_digest = strdup_s(copts->compressed_digest);
    opts->writable = copts->writable;

    opts->opts = calloc_s(1, sizeof(struct layer_store_mount_opts));
    if (opts->opts == NULL) {
        printf("Memory out");
        goto err_out;
    }    

    if (mount_label != NULL) {
        opts->opts->mount_label = strdup_s(mount_label);
    }    

    if (copts->storage_opts != NULL) {
        opts->opts->mount_opts = calloc_s(1, sizeof(json_map_string_string));
        if (opts->opts->mount_opts == NULL) {
            printf("Memory out");
            goto err_out;
        }
        if (dup_json_map_string_string(copts->storage_opts, opts->opts->mount_opts) != 0) { 
            printf("Failed to dup storage opts");
            goto err_out;
        }
    }    

    goto out; 

err_out:
    free(opts);
    opts = NULL;

out:
    return opts;
}

int storage_layer_create(const char *layer_id, storage_layer_create_opts_t *copts) {
	int ret = 0;
	struct io_read_wrapper *reader = NULL;
	struct layer_opts *opts = NULL;
	if(copts == NULL) {
		printf("Create opts is null\n");
	}
	if(!copts->writable && copts->layer_data_path == NULL) {
		printf("Invalid arguments for put ro layer\n");
		ret = -1;
		goto out;
	}
	if(fill_read_wrapper(copts->layer_data_path, &reader) != 0) {
		printf("Failed to fill layer read wrapper\n");
		ret = -1;
		goto out;
	}
	opts = fill_create_layer_opts(copts, NULL);
	if(opts == NULL) {
		printf("Failed to fill create ro layer options\n");
		ret = -1;
		goto out;
	}
	ret = layer_store_create(layer_id, opts, reader, NULL);
	if(ret != 0) {
		printf("Failed to call layer store create\n");
		ret = -1;
		goto out;
	}
out:
	if(reader != NULL) {
		if(reader->close != NULL) {
			reader->close(reader->context, NULL);
		}
		free(reader);
	}
	free(opts);
	return ret;
}

static int do_create_container_rw_layer(const char *container_id, const char *image_top_layer, const char *mount_label, json_map_string_string *storage_opts) {
	int ret = 0;
	struct layer_opts *opts = NULL;
	storage_layer_create_opts_t copts = {
	 	.parent = image_top_layer,
		.writable = true,
		.storage_opts = storage_opts,
	};
	opts = fill_create_layer_opts(&copts, mount_label);
	if(opts == NULL) {
		printf("Failed to fill create opts\n");
		ret = -1;
		goto out;
	}
	if(layer_store_create(container_id, opts, NULL, NULL) != 0) {
		printf("Failed to create container rootfs, layer\n");
		ret = -1;
		goto out;
	}
out:
	free(opts);
	return ret;
}

int storage_rootfs_create(const char *container_id, const char *image, const char *mount_label,
                          json_map_string_string *storage_opts, char **mountpoint)
{
    int ret = 0; 
    char *rootfs_id = NULL;
	image_t *img = NULL;
    image_summary *image_summary = NULL;
	char *normalized_name = NULL;
    struct layer *layer_info = NULL;
    if (container_id == NULL || image == NULL) {
        printf("Invalid arguments for rootfs create\n");
        ret = -1;
        goto out; 
    }    
	normalized_name = oci_normalize_image_name(image);
	img = lookup(normalized_name);
	if(img == NULL) {
		printf("Image not known\n");
		ret = -1;
		goto out;
	}
    image_summary = storage_img_get_summary(image);
    if (image_summary == NULL) {
        printf("No such image:%s\n", image);
        ret = -1;
        goto out;
    }   

    // note: we use container id as the layer id of the container
    if (do_create_container_rw_layer(container_id, img->simage->layer, mount_label, storage_opts) != 0) { 
        printf("Failed to do create rootfs layer\n");
        ret = -1;
        goto out;
    }    

    rootfs_id = rootfs_store_create(container_id, NULL, 0, img->simage->id, container_id, NULL, NULL);
    if (rootfs_id == NULL) {
        printf("Failed to create rootfs\n");
        ret = -1;
        goto remove_layer;
    }    

    layer_info = layer_store_lookup(container_id);
    if (layer_info == NULL) {
        printf("Failed to get created rootfs layer info\n");
        ret = -1;
        goto remove_layer;
    }    
    if (mountpoint != NULL) {
        *mountpoint = strdup_s(layer_info->mount_point);
    }
	goto out;
remove_layer:
    if (layer_store_delete(container_id) != 0) {
        printf("Failed to delete layer %s due rootfs create fail\n", container_id);
    }

out:
    if(rootfs_id != NULL) {
		free(rootfs_id);
	}
    free_image_summary(image_summary);
    free_layer(layer_info);
	if(normalized_name != NULL) {
		free(normalized_name);
	}
    return ret;
}

int storage_rootfs_delete(const char *container_id) {
	int ret = 0;
	storage_rootfs *rootfs_info = NULL;

	if(container_id == NULL) {
		printf("Invalid input arguments\n");
		return -1;
	}
	
	rootfs_info = rootfs_store_get_rootfs(container_id);
	if(rootfs_info == NULL) {
		printf("Failed to get rootfs %s info\n", container_id);
		ret = -1;
		goto out;
	}

	if(layer_store_delete(rootfs_info->layer) != 0) {
		printf("Failed to remove layer %s\n", rootfs_info->layer);
		ret = -1;
		return ret;
	}

	if(delete_rootfs_from_store(container_id) != 0) {
		printf("Failed to remove rootfs %s\n", container_id);
		ret = -1;
		goto out;
	}
out:
	free_storage_rootfs(rootfs_info);
	return ret;
}

char *storage_rootfs_mount(const char *container_id)
{
    char *mount_point = NULL;
    storage_rootfs *rootfs_info = NULL;

    if (container_id == NULL) {
        printf("Invalid input arguments");
        goto out; 
    }    

    rootfs_info = rootfs_store_get_rootfs(container_id);
    if (rootfs_info == NULL) {
        printf("Failed to get rootfs %s info\n", container_id);
        goto out; 
    }    

    mount_point = layer_store_mount(rootfs_info->layer);
    if (mount_point == NULL) {
        printf("Failed to mount %s\n", rootfs_info->layer);
        goto out; 
    }    

out:
    free_storage_rootfs(rootfs_info);
    return mount_point;
}

int storage_rootfs_umount(const char *container_id, bool force) {
	int ret = 0;
	storage_rootfs *rootfs_info = NULL;

	if(container_id == NULL) {
		printf("Invalid input arguments\n");
		ret = -1;
		goto out;
	}

	rootfs_info = rootfs_store_get_rootfs(container_id);
	if(rootfs_info == NULL) {
		printf("Failed to get rootfs %s info, skip umount\n", container_id);
		ret == 0;
		goto out;
	}

	if(layer_store_umount(rootfs_info->layer, force) != 0) {
		printf("Failed to umount layer %s\n", rootfs_info->layer);
		ret = -1;
		goto out;
	}
out:
	free_storage_rootfs(rootfs_info);
	return ret;
}

char *get_container_mount_point(const char *image_name) {
	char *id = NULL;
	char *mount_point = NULL;
	
	id = rootfs_store_get_id(image_name);
	if(id == NULL) {
		return NULL;
	}

	mount_point = storage_rootfs_mount(id);

out:
	free(id);
	return mount_point;
} 

int umount_point(const char *container_id) {
	char *id = NULL;
	int ret = 0;
	
	id = rootfs_store_get_id(container_id);
	if(id == NULL) {
		return -1;
	}

	ret = storage_rootfs_umount(id, true);
	if(ret != 0) {
		printf("err umount rootfs\n");	
	}

out:
	free(id);
	return ret;
}

static int with_valid_converted_config(const char *path, bool *valid)
{
    int ret = 0;
    int nret;
    char image_path[PATH_MAX] = { 0x00 };
    char config_path[PATH_MAX] = { 0x00 };
    char *base_name = NULL;
    char *sha256_key = NULL;
    storage_storage *img = NULL;
    parser_error err = NULL;
    docker_image_config_v2 *v2_config = NULL;

    *valid = false;

    nret = snprintf(image_path, sizeof(image_path), "%s/%s", path, IMAGE_JSON);
    if (nret < 0 || (size_t)nret >= sizeof(image_path)) {
        printf("Failed to get image path\n");
        ret = -1;
        goto out;
    }

    img = storage_storage_parse_file(image_path, NULL, &err);
    if (img == NULL) {
        printf("Failed to parse image json file : %s\n", err);
        ret = -1;
        goto out;
    }

    sha256_key = calc_full_digest(img->id);
    if (sha256_key == NULL) {
        printf("Failed to get sha256 key\n");
        ret = -1;
        goto out;
    }

    base_name = make_big_data_base_name(sha256_key);
    if (base_name == NULL) {
        printf("Failed to retrieve oci image spec file's base name\n");
        ret = -1;
        goto out;
    }

    nret = snprintf(config_path, sizeof(config_path), "%s/%s", path, base_name);
    if (nret < 0 || (size_t)nret >= sizeof(config_path)) {
        printf("Failed to get big data config path\n");
        ret = -1;
        goto out;
    }

    if (!file_exists(config_path)) {
        printf("version 1 format image\n");
        goto out;
    }

    free(err);
    err = NULL;
    v2_config = docker_image_config_v2_parse_file(config_path, NULL, &err);
    if (v2_config == NULL) {
        printf("Invalid config big data : %s\n", err);
        ret = -1;
        goto out;
    }

    *valid = true;

out:
    free(err);
    free_docker_image_config_v2(v2_config);
    free_storage_storage(img);
    free(base_name);
    free(sha256_key);
    return ret;
}

static int validate_manifest_schema_v1(const char *path, bool *valid) {
	int ret = 0; 
    int nret;
    registry_manifest_schema1 *manifest_v1 = NULL;
    registry_manifest_schema2 *manifest_v2 = NULL;
    oci_image_manifest *manifest_oci = NULL;
    parser_error err = NULL;
    char manifest_path[PATH_MAX] = { 0x00 };
    bool valid_v2_config = false;

    *valid = false;
    nret = snprintf(manifest_path, sizeof(manifest_path), "%s/%s", path, IMAGE_DIGEST_BIG_DATA_KEY);
    if (nret < 0 || (size_t)nret >= sizeof(manifest_path)) {
        printf("Failed to get big data manifest path\n");
        ret = -1;
        goto out; 
    }    

    manifest_v2 = registry_manifest_schema2_parse_file(manifest_path, NULL, &err);
    if (manifest_v2 != NULL) {
        goto out; 
    }    

    free(err);
    err = NULL;

    manifest_oci = oci_image_manifest_parse_file(manifest_path, NULL, &err);
    if (manifest_oci != NULL) {
        goto out; 
    }    

    free(err);
    err = NULL;

    manifest_v1 = registry_manifest_schema1_parse_file(manifest_path, NULL, &err);
    if (manifest_v1 == NULL) {
        printf("Invalid manifest format\n");
        ret = -1;
        goto out; 
    }    
	
	if(with_valid_converted_config(path, &valid_v2_config) != 0) {
		printf("Failed to validate converted config\n");
		ret = -1;
		goto out;
	}
	
	*valid = (manifest_v1->schema_version == 1) && !valid_v2_config;

out:
	free(err);
	free_registry_manifest_schema1(manifest_v1);
    free_registry_manifest_schema2(manifest_v2);
    free_oci_image_manifest(manifest_oci);
    return ret;
}

static int append_image_by_directory(const char *image_dir) {
	int ret = 0;
	int nret = 0;
	char image_path[PATH_MAX] = { 0x00 };
	image_t *img = NULL;
	storage_storage *im = NULL;
	parser_error err = NULL;

	nret = snprintf(image_path, sizeof(image_path), "%s/%s", image_dir, IMAGE_JSON);
	if(nret < 0 || (size_t)nret >= sizeof(image_path)) {
		printf("Failed to get image path\n");
		return -1;
	}
	im = storage_storage_parse_file(image_path, NULL, &err);
	if(im == NULL) {
		printf("Failed to parse images path : %s\n", err);
		ret = -1;
		goto out;
	}
	img = (image_t *)calloc_s(1, sizeof(image_t));
	img->refcnt = 1;
	try_fill_image_spec(img, im->id, storage_dir);
	img->simage = im;
	im = NULL;
	if(append_image(img->simage->id, img->simage->digest, img) != 0) {
		printf("Failed to append image to image store!\n");
		ret = -1;
		goto out;
	}
out:
	if(ret != 0) {
		free(img);
	}
	free_storage_storage(im);
	free(err);
	return ret;
}

int image_store_init() {
	int ret = 0;
	int nret = 0;
	char **image_dirs = NULL;
	size_t image_dirs_num = 0;
	char image_path[PATH_MAX] = { 0x00 };
	size_t i = 0;
	
	if(g_image_store == NULL) {
		g_image_store = (image_store_t*)malloc(sizeof(image_store_t));
		g_image_store->image_list = (struct image_list_elem*)malloc(sizeof(struct image_list_elem));
		g_image_store->image_list->next = NULL;
		g_image_store->dir = "/var/lib/docker-mini/overlay-images";
	}
	
	ret = mkdir_p(g_image_store->dir, 0600);
	if(ret  < 0) {
		printf("Unable to create image store directory %s : %s.\n", g_image_store->dir, strerror(errno));
		ret = -1;
		goto out;
	}

	ret = list_all_subdir(g_image_store->dir, &image_dirs, &image_dirs_num);
	if(ret != 0) {
		printf("Failed to get images directory\n");
		goto out;
	}

	for(i = 0; i < image_dirs_num; i++) {
		bool valid_v1_image = NULL;

		printf("Restore the images:%s\n", image_dirs[i]);
		nret = snprintf(image_path, sizeof(image_path), "%s/%s", g_image_store->dir, image_dirs[i]);
		if(nret < 0 || (size_t)nret >= sizeof(image_path)) {
			printf("Failed to get image path\n");
			continue;
		}

		if(validate_manifest_schema_v1(image_path, &valid_v1_image) != 0) {
			printf("Failed to validate manifest schema version1 format\n");
			continue;
		}
		
		if(!valid_v1_image) {
			if(append_image_by_directory(image_path) != 0) {
				printf("Found image path but load json failed : %s\n", image_dirs[i]);
				continue;
			}
		} else {
			
		}
	}
out:
	free_array(image_dirs);
	return ret;
}
