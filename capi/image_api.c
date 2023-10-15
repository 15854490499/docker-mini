#include "image_api.h"
#include "registry.h"
#include "storage.h"
#include "layer.h"
#include "rootfs.h"
#include "utils.h"
#include "log.h"

int oci_init() {
	int ret = 0;
	
	ret = image_store_init();
	if(ret != 0) {
		LOG_ERROR("image store init err\n");
		ret = -1;
		goto out;
	}
	ret = layer_store_init();
	if(ret != 0) {
		LOG_ERROR("layer store init err\n");
		ret = -1;
		goto out;
	}
	ret = rootfs_store_init();
	if(ret != 0) {
		LOG_ERROR("rootfs store init err\n");
		ret = -1;
		goto out;
	}

out:
	return ret;
}

static bool check_im_pull_args(const im_pull_request *request, im_pull_response* const *response) {
	if(request == NULL || response == NULL) {
		LOG_ERROR("Request or response is NULL\n");
		return false;
	}

	if(request->image == NULL) {
		LOG_ERROR("Empty image required\n");
		return false;
	}
	return true;
}

static int pull_image(const im_pull_request *request, char **name) {
	int ret = -1;
	registry_pull_options *options = NULL;
	char *host = NULL;
	char *with_tag = NULL;
	
	options = (registry_pull_options*)common_calloc_s(sizeof(registry_pull_options));
	if(options == NULL) {
		LOG_ERROR("Out of memory\n");
		goto out;
	}

	if(request->auth != NULL) {
		
	}  else {
		options->auth.username = strdup_s(request->username);
		options->auth.password = strdup_s(request->password);
	}

	options->dest_image_name = oci_normalize_image_name(request->image);
	with_tag = oci_default_tag(request->image);
	host = default_host;
	options->insecure_registry = false;
	options->image_name = oci_add_host(host, with_tag);
	ret = registry_pull(options);
	if(ret != 0) {
		LOG_ERROR("registry pull failed\n");
		goto out;
	}

	*name = strdup_s(options->dest_image_name);
out:
	if(with_tag != NULL) {
		free(with_tag);
	}
	free_registry_pull_options(options);
	return ret;
}

static int oci_do_pull_image(const im_pull_request *request, im_pull_response *response) {
	int ret = 0;
	image_summary *image = NULL;
	char *dest_image_name = NULL;

	if(request == NULL || request->image == NULL || response == NULL) {
		LOG_ERROR("Invalid NULL param\n");
		return -1;
	}
	
	ret = pull_image(request, &dest_image_name);
	if(ret != 0) {
		LOG_ERROR("pull image %s failed\n", request->image);
		ret = -1;
		goto out;
	}

	image = storage_img_get_summary(dest_image_name);
	if(image == NULL) {
		LOG_ERROR("get image %s failed after pulling\n", dest_image_name);
		ret = -1;
		goto out;
	}

	response->image_ref = strdup_s(image->id);

out:
	free_image_summary(image);
	free(dest_image_name);
	return ret;
}

static int oci_prepare_rf(const im_prepare_request *request, char **real_rootfs) {
	int ret = 0;
	char *id = NULL;
	char *mount_point = NULL;

	if(request == NULL) {
		LOG_ERROR("request is NULL\n");
		return -1;
	}

	id = strdup_s(request->container_id);
	ret = storage_rootfs_create(id, request->image_name, request->mount_label, NULL, real_rootfs);
	if(ret != 0) {
		LOG_ERROR("Failed to create container rootfs:%s\n", request->container_id);
		ret = -1;
		goto out;
	}
	mount_point = storage_rootfs_mount(id);
	if(mount_point == NULL) {
		ret = -1;
		goto out;
	}
	ret = storage_rootfs_umount(id, false);
	if(ret != 0) {
		ret = -1;
		goto out;
	}
	
out:
	free(id);
	if(mount_point != NULL) {
		free(mount_point);
	}
	return ret;
}

static int oci_delete_rf(const im_delete_rootfs_request *request) {
	if(request == NULL) {
		LOG_ERROR("Request is NULL\n");
		return -1;
	}

	return storage_rootfs_delete(request->name_id);
}

static char *oci_resolve_image_name(const char *name) {
	if(name == NULL) {
		return NULL;
	}

	if(storage_image_exist(name)) {
		return strdup_s(name);
	}

	return oci_normalize_image_name(name);
}

static int oci_rm_image(const im_rmi_request *request) {
	int ret = 0;
	char *image_id = NULL;
	char *real_image_name = NULL;
	char **image_names = NULL;
	size_t image_names_len = 0;
	char **reduced_image_names = NULL;
	size_t reduced_image_names_len = 0;
	size_t i;

	if(request == NULL || request->image == NULL) {
		LOG_ERROR("Invalid input arguments\n");
		return -1;
	}

	if(!valid_image_name(request->image)) {
		LOG_ERROR("Invalid image name: %s\n", request->image);
		ret = -1;
		goto out;
	}

	real_image_name = oci_resolve_image_name(request->image);
	if(real_image_name == NULL) {
		LOG_ERROR("Failed to resolve image name\n");
		ret = -1;
		goto out;
	}

	if(storage_img_get_names(real_image_name, &image_names, &image_names_len) != 0) {
		LOG_ERROR("Get image %s names failed\n", real_image_name);
		ret = -1;
		goto out;
	}

	image_id = storage_img_get_image_id(real_image_name);
	if(image_id == NULL) {
		LOG_ERROR("Get id of image %s failed\n", real_image_name);
		ret = -1;
		goto out;
	}

	if(image_names_len == 1 || has_prefix(image_id, real_image_name)) {
		ret = storage_img_delete(real_image_name, true);
		if(ret != 0) {
			LOG_ERROR("Failed to remove image %s\n", real_image_name);
		}
		goto out;
	}

	reduced_image_names = (char**)calloc_s(sizeof(char*), image_names_len - 1);
	if(reduced_image_names == NULL) {
		LOG_ERROR("Out of memory\n");
		ret = -1;
		goto out;
	}

	for(i = 0; i < image_names_len; i++) {
		if(strcmp(image_names[i], real_image_name) != 0) {
			reduced_image_names[reduced_image_names_len] = strdup_s(image_names[i]);
			if(reduced_image_names[reduced_image_names_len] == NULL) {
				LOG_ERROR("Out of memory\n");
				ret = -1;
				goto out;
			}
			reduced_image_names_len++;
		}
	}

	ret = storage_img_set_names(real_image_name, (const char**)reduced_image_names, reduced_image_names_len);
	if(ret != 0) {
		LOG_ERROR("Failed to set names of image %s\n", real_image_name);
		goto out;
	}

out:
	free(real_image_name);
	free(image_id);
	free_array_by_len(image_names, image_names_len);
	free_array_by_len(reduced_image_names, image_names_len - 1);
	return ret;
}

int im_pull_image(const im_pull_request *request, im_pull_response **response) {
	int ret = -1;
	im_pull_response *tmp_res = NULL;

	if(!check_im_pull_args(request, response)) {
		return ret;
	}

	tmp_res = (im_pull_response *)common_calloc_s(sizeof(im_pull_response));
	if(tmp_res == NULL) {
		LOG_ERROR("Out of memory\n");
		goto out;
	}
	
	ret = oci_do_pull_image(request, tmp_res);
	if(ret != 0) {
		LOG_ERROR("Pull image %s failed\n", request->image);
		ret = -1;
		goto out;
	}
out:
	if(ret != 0 && tmp_res != NULL) {
		tmp_res->errmsg = strdup_s("error image pull");
	}
	*response = tmp_res;
	return ret;
}

int im_prepare_container_rootfs(const im_prepare_request *request, char **real_rootfs) {
	int ret = 0;
	int nret = 0;
	
	if(request == NULL) {
		LOG_ERROR("Invalid input arguments\n");
		return -1;
	}
	
	if(request->container_id == NULL) {
		LOG_ERROR("Contaienr prepare need container id\n");
		ret = -1;
		goto out;
	}

	if(request->image_type == NULL) {
		LOG_ERROR("Missing image type\n");
		ret = -1;
		goto out;
	}

	nret = oci_prepare_rf(request, real_rootfs);
	if(nret != 0) {
		LOG_ERROR("Failed to prepare container rootfs %s with image %s type %s\n", request->container_id, request->image_name, request->image_type);
		ret = -1;
		goto out;
	}

out:
	return ret;
}

int im_remove_container_rootfs(const char *container_id) {
	int ret = 0;
	im_delete_rootfs_request *request = NULL;

	if(container_id == NULL) {
		LOG_ERROR("Invalid input arguments\n");
		ret = -1;
		goto out;
	}

	request = common_calloc_s(sizeof(im_delete_rootfs_request));
	if(request == NULL) {
		LOG_ERROR("Out of memory\n");
		ret = -1;
		goto out;
	}

	request->name_id = strdup_s(container_id);
	ret = oci_delete_rf(request);
	if(ret != 0) {
		LOG_ERROR("Failed to delete rootfs for container %s\n", container_id);
		ret = -1;
		goto out;
	}

out:
	free_im_delete_rootfs_request(request);
	return ret;
}

int im_rm_image(const im_rmi_request *request, im_remove_response **response) {
	int ret = -1;
	char *image_ref = NULL;
	
	if(request == NULL || response == NULL) {
		LOG_ERROR("Invalid input arguments\n");
		return -1;
	}

	*response = common_calloc_s(sizeof(im_remove_response));
	if(*response == NULL) {
		LOG_ERROR("Out of memory\n");
		return -1;
	}

	if(request->image == NULL) {
		LOG_ERROR("remove image requires image ref\n");
		goto pack_response;
	}

	image_ref = strdup_s(request->image);

	ret = oci_rm_image(request);
	if(ret != 0) {
		LOG_ERROR("Failed to remove image %s\n", image_ref);
		ret = -1;
		goto pack_response;
	}

	printf("removed %s\n", image_ref);
pack_response:
	if(ret != 0) {
		(*response)->errmsg = strdup_s("Failed to rm image");
	}
	free(image_ref);
	return ret;
}

void free_im_pull_request(im_pull_request *req)
{
    if (req == NULL) {
        return;
    }    
    free(req->type);
    req->type = NULL;
    free(req->image);
    req->image = NULL;
	if(req->username != NULL)
    	free(req->username);
    req->username = NULL;
	if(req->password != NULL)
    	free(req->password);
    req->password = NULL;
	if(req->auth != NULL )
    	free(req->auth);
    req->auth = NULL;
	if(req->registry_token != NULL)
    	free(req->registry_token);
    req->registry_token = NULL;
	if(req->identity_token != NULL)
    	free(req->identity_token);
    req->identity_token = NULL;
    free(req);
}

void free_im_pull_response(im_pull_response *resp)
{
    if (resp == NULL) {
        return;
    }
	if(resp->image_ref != NULL)
    	free(resp->image_ref);
    resp->image_ref = NULL;
	if(resp->errmsg != NULL)
    	free(resp->errmsg);
    resp->errmsg = NULL;
    free(resp);
}

void free_im_prepare_request(im_prepare_request *request) {
	if(request == NULL) {
		return;
	}
	
	if(request->image_name != NULL) {
		free(request->image_name);
	}
	if(request->container_id != NULL) {
		free(request->container_id);
	}
	if(request->rootfs != NULL) {
		free(request->rootfs);
	}
	if(request->image_type != NULL) {
		free(request->image_type);
	}
	if(request->mount_label != NULL) {
		free(request->mount_label);
	}

	free(request);
}

void free_im_delete_rootfs_request(im_delete_rootfs_request *request) {
	if(request == NULL) {
		return;
	}

	if(request->name_id != NULL) {
		free(request->name_id);
	}

	free(request);
}

void free_im_rmi_request(im_rmi_request *request) {
	if(request == NULL) {
		return;
	}

	if(request->image != NULL) {
		free(request->image);
	}

	free(request);
}

void free_im_remove_response(im_remove_response *response) {
	if(response == NULL) {
		return;
	}

	if(response->errmsg != NULL) {
		free(response->errmsg);
	}

	free(response);
}
