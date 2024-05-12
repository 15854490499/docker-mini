#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "grpc_connect.h"
#include "container_client.h"
#include "image_client.h"

#include "utils.h"

ABSL_FLAG(std::string, target, DEFAULT_ADDR, "Server address");

static grpc_connect_ops g_grpc_connect_ops;

int grpc_connect_ops_init() {
	memset(&g_grpc_connect_ops, 0, sizeof(g_grpc_connect_ops));
	if(container_client_ops_init(&g_grpc_connect_ops) != 0) {
		return -1;
	}

	if(image_client_ops_init(&g_grpc_connect_ops) != 0) {
		return -1;
	}

	return 0;
}

grpc_connect_ops *get_grpc_connect_ops() {
	return &g_grpc_connect_ops;
}

client_connect_config get_connect_config() {
	client_connect_config res = { 0x00 };

	std::string target_str = absl::GetFlag(FLAGS_target);

	res.socket = strdup_s(target_str.c_str());

	return res;
}

void free_connect_config(client_connect_config *config) {

	if(config->socket != NULL) {
		free(config->socket);
	}

	return;
}
