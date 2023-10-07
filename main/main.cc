#include <iostream>
#include <locale.h>

#include "parse_cmd.h"

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

	int ret = 0;
	struct command_parameter *cmd = NULL;
	
	command_parameters_init(&cmd);
	if(cmd == NULL) {
		printf("command parameters init err\n");
		return -1;
	}

	ret = parse_command_parameters(cmd, argc, argv);
	if(ret != 0) {
		printf("parse command parameters err\n");
		goto out;
	}

	ret = execute_command(cmd);
	if(ret != 0) {
		printf("command execution err\n");
		goto out;
	}

out:
	free_command_parameters(cmd);
	return ret;
}
