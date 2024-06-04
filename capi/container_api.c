#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>

#include "utils.h"
#include "storage.h"
#include "container_api.h"
#include "image_api.h"
#include "lxcapi.h"
#include "log.h"

#ifdef DAEMON_COMPILE

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

static int save_runtime_file(const char *id, const char *container_spec) {
	int ret = 0;
	char spec_path[PATH_MAX] = { 0x00 };
	char spec_dir[PATH_MAX] = { 0x00 };

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

out:
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
	ret = save_runtime_file(id, container_spec);
	if(ret != 0) {
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

static int start_request_check(const container_start_request *request) {
	int ret = 0;

	if(request->id == NULL) {
		LOG_ERROR("invalid Null container id");
		ret = -1;
		goto out;	
	}

out:
	return ret;
}

static int renew_oci_config(oci_runtime_spec *container_spec, const char *mount_point) {
	int ret = 0;
	oci_runtime_spec_root *root = NULL;
	
	root = common_calloc_s(sizeof(oci_runtime_spec_root));
	if(root == NULL) {
		LOG_ERROR("memory out\n");
		return -1;
	}
	
	root->path = strdup_s(mount_point);
	if(root->path == NULL) {
		ret = -1;
		goto out;
	}

	root->readonly = false;
	
	container_spec->root = root;
	
out:
	if(ret != 0) {
		free(root);
		root = NULL;
	}

	return ret;
}

static int do_start_container(const char *id) {
	int ret = 0;
	int nret = 0;
	char bundle[PATH_MAX] = { 0x00 };
	char spec_path[PATH_MAX] = { 0x00 };
	char *mount_point = NULL;
	char *json_data = NULL;
	parser_error err = NULL;
	oci_runtime_spec *container_spec = NULL;

	nret = snprintf(bundle, sizeof(bundle), "%s/%s", run_dir, id);
	if(nret < 0 || nret >= sizeof(bundle)) {
		LOG_ERROR("Failed to get runtime path by id : %s", id);
		return -1;
	}
	
	nret = snprintf(spec_path, sizeof(spec_path), "%s/%s/%s", runtime_dir, id, RUNTIME_JSON);
	if(nret < 0 || nret >= sizeof(spec_path)) {
		LOG_ERROR("Failed to get runtime json by id : %s", id);
		return -1;
	}

	container_spec = oci_runtime_spec_parse_file(spec_path, NULL, &err);
	if(container_spec == NULL) {
		LOG_ERROR("Failed to parse the container_spec : %s", err);
		return -1;
	}

	mount_point = container_get_mount_point(id);
	if(mount_point == NULL) {
		LOG_ERROR("mount container rootfs failed\n");
		ret = -1;
		goto out;
	}
	
	if(renew_oci_config(container_spec, mount_point) != 0) {
		LOG_ERROR("renew container spec failed\n");
		ret = -1;
		goto out;
	}
	
	json_data = oci_runtime_spec_generate_json(container_spec, NULL, &err);
	if(json_data == NULL) {
		LOG_ERROR("get container_spec failed : %s", err ? err : "");
		ret = -1;
		goto out;
	}
	
	container_spec->hostname = strdup_s(id); 
	if(save_runtime_file(id, json_data) != 0) {
		ret = -1;
		goto out;
	}

	ret = runtime_create(id, container_spec);
	if(ret != 0) {
		LOG_ERROR("runtime create failed");
		ret = -1;
		goto out;
	}

	LOG_INFO("runtime create success");
	
	ret = runtime_start(id, bundle);
	if(ret != 0) {
		LOG_ERROR("runtime start failed");
		ret = -1;
		goto out;
	}

out:
	if(mount_point != NULL) {
		free(mount_point);
	}
	
	if(ret != 0) {
		container_umount_point(id);
	}

	free_oci_runtime_spec(container_spec);
	return ret;
}

int container_start(const container_start_request *request, container_start_response **response) {
	int ret = 0;
	char *id = NULL;
	
	if(response == NULL) {
		LOG_ERROR("resp is NULL\n");
		return -1;
	}

	*response = (container_start_response*)common_calloc_s(sizeof(container_start_response));
	if(*response == NULL) {
		LOG_ERROR("Out of memory\n");
		return -1;
	}
	
	if(start_request_check(request) != 0) {
		ret = -1;
		goto out;
	}
	
	id = request->id;

	ret = do_start_container(id);
	if(ret != 0) {
		LOG_ERROR("Failed to start container");
		ret = -1;
		goto out;
	}

out:
	if(ret != 0) {
		(*response)->errmsg = strdup_s("error start container");
	}
	(*response)->id = strdup_s(id);

	return ret;
}

static int stop_request_check(const container_stop_request *request) {
	int ret = 0;

	if(request->id == NULL) {
		LOG_ERROR("invalid Null container id");
		ret = -1;
		goto out;	
	}

out:
	return ret;
}

static void runtime_resource_clear(const char *id) {
	int ret = 0;
	int nret = 0;
	char bundle[PATH_MAX] = { 0x00 };
	char mount_spec_path[PATH_MAX] = { 0x00 };

	nret = snprintf(mount_spec_path, sizeof(mount_spec_path), "%s/%s.json", run_dir, id);
	if(nret < 0 || nret >= sizeof(mount_spec_path)) {
		LOG_ERROR("Failed to get mount spec path by id : %s", id);
		return -1;
	}
	
	if(file_exists(mount_spec_path)) {
		path_remove(mount_spec_path);
	}

	nret = snprintf(bundle, sizeof(bundle), "%s/%s", run_dir, id);
	if(nret < 0 || nret >= sizeof(bundle)) {
		LOG_ERROR("Failed to get runtime path by id : %s", id);
		return -1;
	}

	if(dir_exists(bundle)) {
		recursive_remove_path(bundle);
		return;
	}

	return;
}

int container_stop(const container_stop_request *request, container_stop_response **response) {
	int ret = 0;
	char *id = NULL;
	
	if(response == NULL) {
		LOG_ERROR("resp is NULL\n");
		return -1;
	}

	*response = (container_stop_response*)common_calloc_s(sizeof(container_stop_response));
	if(*response == NULL) {
		LOG_ERROR("Out of memory\n");
		return -1;
	}
	
	if(stop_request_check(request) != 0) {
		ret = -1;
		goto out;
	}
	
	id = request->id;

	container_umount_point(id);

	ret = runtime_stop(id);
	if(ret != 0) {
		LOG_ERROR("Failed to stop container");
		ret = -1;
		goto out;
	}

	runtime_resource_clear(id);
	
out:
	if(ret != 0) {
		(*response)->errmsg = strdup_s("error stop container");
	}
	(*response)->id = strdup_s(id);

	return ret;
}

int container_remove(const container_remove_request *request, container_remove_response **response) {
	int ret = 0;
	int nret = 0;
	char bundle[PATH_MAX] = { 0x00 };

	if(request == NULL || response == NULL) {
		LOG_ERROR("Invalid NULL input\n");
		return -1;
	}

	*response = common_calloc_s(sizeof(container_remove_response));
	if(*response == NULL) {
		LOG_ERROR("Out of memory\n");
		goto out;
	}
	
	if(im_remove_container_rootfs(request->id)) {
		ret = -1;
		goto out;
	}
	
	nret = snprintf(bundle, sizeof(bundle), "%s/%s", runtime_dir, request->id);
	if(nret < 0 || nret >= sizeof(bundle)) {
		LOG_ERROR("Failed to get mount spec path by id : %s", request->id);
		return -1;
	}
	
	if(dir_exists(bundle)) {
		recursive_remove_path(bundle);
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

#else

static int attach_request_check(const container_attach_request *request) {
	int ret = 0;

	if(request->id == NULL) {
		LOG_ERROR("invalid Null container id");
		ret = -1;
		goto out;	
	}

out:
	return ret;
}

static int do_attach_container(const char *id) {
	int ret = 0;
	int nret = 0;
	char bundle[PATH_MAX] = { 0x00 };

	nret = snprintf(bundle, sizeof(bundle), "%s/%s", run_dir, id);
	if(nret < 0 || nret >= sizeof(bundle)) {
		LOG_ERROR("Failed to get runtime path by id : %s", id);
		return -1;
	}
	
	ret = runtime_attach(id, bundle);
	if(ret != 0) {
		LOG_ERROR("runtime start failed");
		ret = -1;
		goto out;
	}

out:
	return ret;
}

int container_attach(const container_attach_request *request, container_attach_response **response) {
	int ret = 0;
	char *id = NULL;
	
	if(response == NULL) {
		LOG_ERROR("resp is NULL\n");
		return -1;
	}

	*response = (container_attach_response*)common_calloc_s(sizeof(container_attach_response));
	if(*response == NULL) {
		LOG_ERROR("Out of memory\n");
		return -1;
	}
	
	if(attach_request_check(request) != 0) {
		ret = -1;
		goto out;
	}
	
	id = request->id;

	ret = do_attach_container(id);
	if(ret != 0) {
		LOG_ERROR("Failed to start container");
		ret = -1;
		goto out;
	}

out:
	if(ret != 0) {
		(*response)->errmsg = strdup_s("error attach container");
	}
	(*response)->id = strdup_s(id);

	return ret;
}

#endif

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
	if(req->container_spec != NULL) {
		free(req->container_spec);
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

void free_container_start_request(container_start_request *req) {
	if(req == NULL) {
		return;
	}
	if(req->id != NULL) {
		free(req->id);
	}

	free(req);
}

void free_container_start_response(container_start_response *resp) {
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

void free_container_stop_request(container_stop_request *req) {
	if(req == NULL) {
		return;
	}
	if(req->id != NULL) {
		free(req->id);
	}

	free(req);
}

void free_container_stop_response(container_stop_response *resp) {
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

void free_container_attach_request(container_attach_request *req) {
	if(req == NULL) {
		return;
	}
	if(req->id != NULL) {
		free(req->id);
	}

	free(req);
}

void free_container_attach_response(container_attach_response *resp) {
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

void free_container_remove_request(container_remove_request *req) {
	if(req == NULL) {
		return;
	}
	
	if(req->id != NULL) {
		free(req->id);
	}

	free(req);
}

void free_container_remove_response(container_remove_response *resp) {
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
