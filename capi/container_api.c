#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>

#include "utils.h"
#include "storage.h"
#include "container_api.h"
#include "image_api.h"
#include "container_utils.h"
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

int container_start(const container_start_request *request, container_start_response **response) {
	int ret = 0;
	char *id = NULL;
	struct start_handler *handler = NULL;
	char *default_args[] = {"/sbin/init", NULL};
	bool started = false;
	char title[2048] = { 0x00 };
	int errnum = 0;
	pid_t pid_first = 0, pid_second = 0;
	
	if(request->id == NULL) {
		LOG_ERROR("invalid Null param");
		return -1;
	}

	id = request->id;
	
	handler = start_handler_init(NULL, id);
	if(handler == NULL) {
		LOG_ERROR("error init start handler");
		return -1;
	}

	pid_first = fork();
	if(pid_first < 0) {
		LOG_ERROR("error creating new process by fork");
		return -1;
	}

	if(pid_first != 0) {
		started = wait_on_daemonized_start(handler, pid_first);
		put_start_handler(handler);
		return 0;
	}
	
	ret = snprintf(title, sizeof(title), "[lxc monitor] %s %s", dockermini_path, id);
	if(ret > 0) {
		ret = setproctitle(title);
		if(ret < 0) {
			LOG_INFO("Failed to set process title to %s", title);
		} else {
			LOG_INFO("Set process title to %s", title);
		}
	}

	pid_second = fork();
	if(pid_second < 0) {
		LOG_ERROR("Failed to fork first child process");
		_exit(EXIT_FAILURE);
	}

	if(pid_second != 0) {
		put_start_handler(handler);
		_exit(EXIT_SUCCESS);
	}

	ret = chdir("/");
	if(ret < 0) {
		LOG_ERROR("Failed to change to \"/\" directory");
		_exit(EXIT_FAILURE);
	}

	ret = inherit_fds(true, handler->keep_fds, 3);
	if(ret < 0) {
		_exit(EXIT_FAILURE);
	}
	
	ret = null_stdfds();
	if(ret < 0) {
		LOG_ERROR("ailed to redirect std{in,out,err} to /dev/null");
		_exit(EXIT_FAILURE);
	}
	
	ret = setsid();
	if(ret < 0) {
		LOG_INFO("Process %d is already process group leader", lxc_raw_getpid());
	}
	
	ret = inherit_fds(true, handler->keep_fds, 3);
	if(ret != 0) {
		put_start_handler(handler);
		ret = -1;
		goto on_error;
	}

	ret = do_start(default_args, handler, &errnum);

}

int container_remove(const container_remove_request *request, container_remove_response **response) {
	int ret = 0;

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
