#include <iostream>
#include <locale.h>

#include "log.h"
#include "service_common.h"

static int set_locale() {
	int ret = 0;
	if(setlocale(LC_CTYPE, "en_US.UTF-8") == NULL) {
		perror("Could not set locale to en_US.UTF-8:");
		ret = -1;
		goto out;
	}
out:
	return ret;
}

int main(int argc, char** argv) {
	if(set_locale() != 0) {
		return -1;
	}
	if(server_common_init() != 0) {
		LOG_ERROR("server start failed\n");
		exit(1);
	}
	server_common_start();

out:
	return 0;
}
