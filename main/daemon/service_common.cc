#include "image_api.h"
#include "grpc_service.h"
#include "service_common.h"
#include "log.h"

int server_common_init() {
	int ret = 0;
	ret = oci_init();
	if(ret != 0) {
		LOG_ERROR("oci init err\n");
		return -1;
	}
	return grpc_server_init();
}

void server_common_start() {
	grpc_server_wait();
}

void server_common_shutdown() {
	grpc_server_shutdown();
}


