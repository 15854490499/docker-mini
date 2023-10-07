#ifndef __IMAGE_API_H__
#define __IMAGE_API_H__

#include <stdbool.h>

#ifdef __cplusplus 
extern "C" {
#endif

#define IMAGE_TYPE_OCI "oci"
#define IMAGE_TYPE_EMBEDDED "embedded"
#define IMAGE_TYPE_EXTERNAL "external"

#define default_host "docker.io"

typedef struct {
	char *type;
	char *image;

	char *username;
	char *password;
	char *auth;
	char *identity_token;
	char *registry_token;
} im_pull_request;

typedef struct {
	char *image_ref;
	char *errmsg;
} im_pull_response;

typedef struct {
    char *image_type;
    char *image_name;
    char *container_id;
    char *rootfs; // only used for external image type
    char *mount_label; // mount label for selinux
} im_prepare_request;

typedef struct {
	char *name_id;
} im_delete_rootfs_request;

typedef struct {
	char *image;
	bool force;
} im_rmi_request;

typedef struct {
	char *errmsg;
} im_remove_response;

int oci_init();
int im_pull_image(const im_pull_request *requset, im_pull_response **response);
int im_prepare_container_rootfs(const im_prepare_request *request, char **real_rootfs);
int im_remove_container_rootfs(const char *container_id);
int im_rm_image(const im_rmi_request *request, im_remove_response **response);
void free_im_pull_request(im_pull_request *req);
void free_im_pull_response(im_pull_response *resp);
void free_im_prepare_request(im_prepare_request *req);
void free_im_delete_rootfs_request(im_delete_rootfs_request *req);
void free_im_rmi_request(im_rmi_request *request);
void free_im_remove_response(im_remove_response *response);

#ifdef __cplusplus
}
#endif

#endif
