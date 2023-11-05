#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>

#include "utils.h"
#include "storage.h"
#include "container_api.h"
#include "image_api.h"
#include "log.h"

#define CONTAINER_ID_MAX_LEN 64
static char *try_generate_id()
{
    int i = 0; 
    int max_time = 10;
    char *id = NULL;
    //container_t *value = NULL;

    id = common_calloc_s((CONTAINER_ID_MAX_LEN + 1)); 
    if (id == NULL) {
    	LOG_ERROR("Out of memory\n");
        return NULL;
    }    

    for (i = 0; i < max_time; i++) {
        if (generate_random_str(id, (size_t)CONTAINER_ID_MAX_LEN)) {
        	LOG_ERROR("Generate id failed\n");
            goto err_out;
        } else {
			goto out;
		}

        /*value = containers_store_get(id);
        if (value != NULL) {
            container_unref(value);
            value = NULL;
            continue;
        } else {
            goto out; 
        }*/
    }    

err_out:
    free(id);
    id = NULL;
out:
    return id;
}

static int maintain_container_id(const container_create_request *request, char **out_id, char **out_name) {
	
	int ret = 0;
	char *id = NULL;
	char *name = NULL;

	id = try_generate_id();
	if(id == NULL) {
		LOG_ERROR("Failed to geneerate conatiner ID\n");
		ret = -1;
		goto out;
	}

	if(request->id != NULL) {
		name = strdup_s(request->id);
	} else {
		name = strdup_s(id);
	}

out:
	*out_id = id;
	*out_name = name;
	return ret;
}

static int do_image_create_container_rootfs_layer(const char *container_id, const char *image_type,
												  const char *image_name, const char *mount_label, const char *rootfs,
												  char **real_rootfs) 
{
	int ret = 0;
	im_prepare_request *request = NULL;

	request = common_calloc_s(sizeof(im_prepare_request));
	if(request == NULL) {
		LOG_ERROR("Out of memory\n");
		ret = -1;
		goto out;
	}
	request->container_id = strdup_s(container_id);
	request->image_name = strdup_s(image_name);
	request->image_type = strdup_s(image_type);
	request->mount_label = strdup_s(mount_label);
	request->rootfs = strdup_s(rootfs);

	if(im_prepare_container_rootfs(request, real_rootfs)) {
		ret = -1;
		goto out;
	}

out:
	free_im_prepare_request(request);
	return ret;
}

int container_create(const container_create_request *request, container_create_response **resp) {
	int ret = 0;
	char *real_rootfs = NULL;
	char *image_type = NULL;
	char *image_name = NULL;
	char *name = NULL;
	char *id = NULL;
	char *container_spec = NULL;
	char spec_path[PATH_MAX] = { 0x00 };
	char spec_dir[PATH_MAX] = { 0x00 };

	if(resp == NULL) {
		LOG_ERROR("resp is NULL\n");
		return -1;
	}

	*resp = (container_create_response*)common_calloc_s(sizeof(container_create_response));
	if(*resp == NULL) {
		LOG_ERROR("Out of memory\n");
		return -1;
	}
	
	image_type = strdup_s(IMAGE_TYPE_OCI);
	image_name = strdup_s(request->image);	
	if(maintain_container_id(request, &id, &name) != 0) {
		ret = -1;
		goto out;
	}
	
	ret = do_image_create_container_rootfs_layer(id, image_type, image_name, NULL, request->rootfs, &real_rootfs);
	if(ret != 0) {
		LOG_ERROR("Can not create container %s rootfs layer\n", id);
		goto out;
	}

	container_spec = request->container_spec;
	ret = snprintf(spec_path, sizeof(spec_path), "%s/%s/%s", runtime_dir, id, RUNTIME_JSON);
	if(ret < 0 || ret >= sizeof(spec_path))  {
		LOG_ERROR("Failed to get runtime path by id : %s", id);
		return -1;
	}

	strcpy(spec_dir, spec_path);
	ret = mkdir_p(dirname(spec_dir), 0700);
	if(ret < 0) {
		LOG_ERROR("Failed to create runtime directory %s.", spec_path);
		return -1;
	}
	if(write_file(spec_path, container_spec, strlen(container_spec), 0666) != 0) {
		LOG_ERROR("Failed to save spec json file");
		ret = -1;
		goto out;
	}

	LOG_INFO("create container %s success", id);
out:
	if(ret != 0)
		(*resp)->errmsg = strdup_s("error create image");
	(*resp)->id = strdup_s(id);
	free(real_rootfs);
	free(image_type);
	free(image_name);
	free(name);
	free(id);
	return ret;
}

int container_delete(const container_delete_request *request, container_delete_response **response) {
	int ret = 0;

	if(request == NULL || response == NULL) {
		LOG_ERROR("Invalid NULL input\n");
		return -1;
	}

	*response = common_calloc_s(sizeof(container_delete_response));
	if(*response == NULL) {
		LOG_ERROR("Out of memory\n");
		goto out;
	}
	
	if(im_remove_container_rootfs(request->id)) {
		ret = -1;
		goto out;
	}

out:
	if(ret != 0) {
		(*response)->errmsg = strdup_s("error delete container");	
	}
	(*response)->id = strdup_s(request->id);

	return ret;
}

char *container_get_mount_point(const char *container_id) {
	char *mp = NULL;

	mp = get_container_mount_point(container_id);
	if(mp == NULL) {
		LOG_ERROR("err get mount point\n");
		return NULL;
	}
	return mp;
}

void container_umount_point(const char *container_id) {
	int ret = 0;

	ret = umount_point(container_id);
	return;
}

void free_container_create_request(container_create_request *req) {
	if(req == NULL) {
		return;
	}
	if(req->id != NULL) {
		free(req->id);
	}
	if(req->rootfs != NULL) {
		free(req->rootfs);
	}
	if(req->image != NULL) {
		free(req->image);
	}
	free(req);
}

void free_container_create_response(container_create_response *resp) {
	if(resp == NULL) {
		return;
	}
	if(resp->id != NULL) {
		free(resp->id);
	}
	if(resp->errmsg != NULL) {
		free(resp->errmsg);
	}
	free(resp);
}

void free_container_delete_request(container_delete_request *req) {
	if(req == NULL) {
		return;
	}
	
	if(req->id != NULL) {
		free(req->id);
	}

	free(req);
}

void free_container_delete_response(container_delete_response *resp) {
	if(resp == NULL) {
		return;
	}

	if(resp->id != NULL) {
		free(resp->id);
	}

	if(resp->errmsg != NULL) {
		free(resp->errmsg);
	}

	free(resp);
}
