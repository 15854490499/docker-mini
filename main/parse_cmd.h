#ifndef __PARSE_CMD_H__
#define __PARSE_CMD_H__


struct command_parameter {
	char *action;
	char *image;
	char *container;

	char *show;
};

void command_parameters_init(struct command_parameter **cmd);
void free_command_parameters(struct command_parameter *cmd);
int parse_command_parameters(struct command_parameter *cmd, int argc, char **argv);
int execute_command(struct command_parameter *cmd);
int do_pull_image(const char *image);
void do_remove_image(const char *image);
void do_create_container(const char *image);
void do_remove_container(const char *container_);
void do_start_container(const char *container_);

#endif
