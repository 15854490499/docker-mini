#ifndef __PARSE_CMD_H__
#define __PARSE_CMD_H__

#include "container_api.h"
#include "image_api.h"

struct command_parameter {
	char *action;
	void *arg;
};

void command_parameters_init(struct command_parameter **cmd);
void free_command_parameters(struct command_parameter *cmd);
int parse_command_parameters(struct command_parameter *cmd, int argc, char **argv);
int execute_command(struct command_parameter *cmd);
int do_pull_image(const im_pull_request *req);
int do_remove_image(const im_remove_request *req);
int do_create_container(const container_create_request *req);
int do_remove_container(const container_remove_request *req);
int do_start_container(const container_start_request *req);

#endif
