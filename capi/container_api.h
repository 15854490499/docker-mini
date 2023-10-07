#ifndef __CONTAINER_API_H__
#define __CONTAINER_API_H__

#ifdef __cplusplus 
extern "C" {
#endif

typedef struct {
	char *id;

	char *rootfs;

	char *image;

} container_create_request;

typedef struct {
	char *id;

	char *errmsg;
} container_create_response;

typedef struct {
	char *id;

	bool force; 
} container_delete_request;

typedef struct {
	char *id;

	uint32_t exit_status;

	char *errmsg;
} container_delete_response;

int container_create(const container_create_request *request, container_create_response **response);
int container_delete(const container_delete_request *request, container_delete_response **response);
char *container_get_mount_point(const char *container_id);
void container_umount_point(const char *container_id);

void free_container_create_request(container_create_request *req);
void free_container_create_response(container_create_response *resp);
void free_container_delete_request(container_delete_request *req);
void free_container_delete_response(container_delete_response *resp);
#ifdef __cplusplus
}
#endif

#endif
