#ifndef __CONTAINER_API_H__
#define __CONTAINER_API_H__

#ifdef __cplusplus 
extern "C" {
#endif

#define runtime_dir "/var/lib/docker-mini/runtime"
#define RUNTIME_JSON "runtime.json"
#define CGROUP_ROOT "/sys/fs/cgroup"

typedef struct {
	char *id;

	char *rootfs;

	char *image;

	char *container_spec;

} container_create_request;

typedef struct {
	char *id;

	char *errmsg;
} container_create_response;

typedef struct {
	char *id;

} container_start_request;

typedef struct {
	char *id;

	char *errmsg;
} container_start_response;

typedef struct {
	char *id;

	bool force; 
} container_remove_request;

typedef struct {
	char *id;

	unsigned int exit_status;

	char *errmsg;
} container_remove_response;

#ifdef DAEMON_COMPILE
int container_create(const container_create_request *request, container_create_response **response);
int container_start(const container_start_request *request, container_start_response **response);
int container_remove(const container_remove_request *request, container_remove_response **response);
char *container_get_mount_point(const char *container_id);
void container_umount_point(const char *container_id);
#endif

void free_container_create_request(container_create_request *req);
void free_container_create_response(container_create_response *resp);
void free_container_start_request(container_start_request *req);
void free_container_start_response(container_start_response *resp);
void free_container_remove_request(container_remove_request *req);
void free_container_remove_response(container_remove_response *resp);
#ifdef __cplusplus
}
#endif

#endif
