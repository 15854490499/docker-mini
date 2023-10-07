#include <iostream>
#include <string.h>

#include "parse_cmd.h"
#include "docker.h"
#include "utils.h"

void command_parameters_init(struct command_parameter **cmd) {
	*cmd = (struct command_parameter*)common_calloc_s(sizeof(struct command_parameter));
	
	(*cmd)->action = NULL;
	(*cmd)->image = NULL;
	(*cmd)->container = NULL;
	(*cmd)->show = NULL;
}

void free_command_parameters(struct command_parameter *cmd) {
	if(cmd == NULL) {
		return;
	}

	if(cmd->action) {
		free(cmd->action);
	}

	if(cmd->image) {
		free(cmd->image);
	}

	if(cmd->container) {
		free(cmd->container);
	}

	if(cmd->show) {
		free(cmd->show);
	}

	free(cmd);
}

int parse_command_parameters(struct command_parameter *cmd, int argc, char **argv) {
	int ret = 0;

	for(int i = 1; i < argc; i++) {
		if(strcmp(argv[i], "pull") == 0 && i + 1 < argc)	{
			cmd->action = strdup_s(argv[i]);
			cmd->image = strdup_s(argv[i+1]);
			i++;
		}
		else if(strcmp(argv[i], "rmi") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			cmd->image = strdup_s(argv[i+1]);
			i++;
		}
		else if(strcmp(argv[i], "create") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			cmd->image = strdup_s(argv[i+1]);
			i++;
		}
		else if(strcmp(argv[i], "rm") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			cmd->container = strdup_s(argv[i+1]);
			i++;
		}
		else if(strcmp(argv[i], "start") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			cmd->container = strdup_s(argv[i+1]);
			i++;
		}
		else {
			std::cout << "invalid params" << std::endl;
			ret = -1;
			break;
		}
	}

	return ret;
}

int do_pull_image(const char *image) {
	int ret = 0;
	std::string id;
	
	docker::ImageManager *manager = new docker::ImageManager;
	id = manager->PullImage(image);
	if(id == "") {
		std::cout << "err pull " << image << std::endl;
		ret = -1;
		goto out;
	}
	
	std::cout << "pulled " << id << std::endl;
out:
	delete manager;
	return ret;
}

void do_remove_image(const char *image) {
	docker::ImageManager *manager = new docker::ImageManager;
	manager->RemoveImage(image);
	delete manager;
}

void do_create_container(const char *image) {
	docker::container container;
	container.create(image, "", image);
}

void do_remove_container(const char *container_) {
	docker::container container;
	container.remove(container_);
}

void do_start_container(const char *container_) {
	docker::container container;
	container.start(container_);
}

int execute_command(struct command_parameter *cmd) {
	int ret = 0;
	char *image = NULL;
	char *container = NULL;

	if(cmd->image) {
		image = cmd->image;
	}

	if(cmd->container) {
		container = cmd->container;
	}

	if(cmd->action) {
		if(strcmp(cmd->action, "pull") == 0) {
			ret = do_pull_image(image);
		}
		else if(strcmp(cmd->action, "rmi") == 0) {
			do_remove_image(image);
		}
		else if(strcmp(cmd->action, "create") == 0) {
			do_create_container(image);
		} 
		else if(strcmp(cmd->action, "rm") == 0) {
			do_remove_container(container);
		}
		else if(strcmp(cmd->action, "start") == 0) {
			do_start_container(container);
		}
	}
		
	return ret;
}
