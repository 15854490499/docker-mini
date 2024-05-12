#ifndef __GRPC_CONNECT_H__
#define __GRPC_CONNECT_H__

#include "container_api.h"
#include "image_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_ADDR "localhost:50051"

typedef struct {

	char *socket;

} client_connect_config;

typedef struct {
	int (*create)(const container_create_request *request, container_create_response *response, void *arg);
	int (*start)(const container_start_request *request, container_start_response *response, void *arg);
	int (*stop)(const container_stop_request *request, container_stop_response *response, void *arg);
	int (*remove)(const container_remove_request *request, container_remove_response *response, void *arg);
} container_ops;

typedef struct {
	int (*pull)(const im_pull_request *request, im_pull_response *response, void *arg);
	int (*remove)(const im_remove_request *request, im_remove_response *response, void *arg);
} image_ops;

typedef struct {
	container_ops container;
	image_ops image;
} grpc_connect_ops;

client_connect_config get_connect_config();
void free_connect_config(client_connect_config *config);
int grpc_connect_ops_init();
grpc_connect_ops *get_grpc_connect_ops();

#ifdef __cplusplus
}
#endif

#endif
