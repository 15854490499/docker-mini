#include <iostream>
#include <locale.h>

#include "parse_cmd.h"

int main(int argc, char** argv) {
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
