#include <iostream>
#include <string.h>

#include "oci_runtime_spec.h"
#include "parse_cmd.h"
#include "utils.h"
#include "log.h"

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
	
	free(cmd->arg);

	free(cmd);
}

static int parse_create_command(int start, int end, char **argv, docker::CreateRequest **req) {
	//oci_runtime_config_linux_resources_pids *pids = NULL;
	oci_runtime_config_linux_resources_cpu *cpu = NULL;
	oci_runtime_config_linux_resources_memory *memory = NULL;
	oci_runtime_config_linux_resources *resources = NULL;
	oci_runtime_config_linux *linux = NULL;
	oci_runtime_spec *container_spec = NULL;
	parser_error err = NULL;
	char *json_data = NULL;
	char spec_path[PATH_MAX] = { 0x00 };
	char spec_dir[PATH_MAX] = { 0x00 };
	int ret = 0;
	
	container_spec = (oci_runtime_spec*)calloc_s(1, sizeof(oci_runtime_spec));
	if(container_spec == NULL) {
		LOG_ERROR("memory out");
		ret = -1;
		goto clean_container_spec;
	}

	container_spec->oci_version = strdup_s("0");

	linux = (oci_runtime_config_linux*)calloc_s(1, sizeof(oci_runtime_config_linux));
	if(linux == NULL) {
		LOG_ERROR("memory out");
		ret = -1;
		goto clean_container_spec;
	}
	
	resources = (oci_runtime_config_linux_resources*)calloc_s(1, sizeof(oci_runtime_config_linux_resources));
	if(resources == NULL) {
		LOG_ERROR("memory out");
		ret = -1;
		goto clean_container_spec;
	}

	memory = (oci_runtime_config_linux_resources_memory*)calloc_s(1, sizeof(oci_runtime_config_linux_resources_memory));
	if(memory == NULL) {
		LOG_ERROR("memory out");
		ret = -1;
		goto clean_container_spec;
	}

	cpu = (oci_runtime_config_linux_resources_cpu*)calloc_s(1, sizeof(oci_runtime_config_linux_resources_cpu));
	if(cpu == NULL) {
		LOG_ERROR("memory out");
		ret = -1;
		goto clean_container_spec;
	}
	
	for(int i = start; i < end; i++) {
		printf("%s\n", argv[i]);
		if((!strcmp(argv[i], "--memory") || !strcmp(argv[i], "-m")) && i + 1 <  end) {
			memory->limit_present = 1;
			memory->limit = std::stoi(argv[++i]);
		} else if(!strcmp(argv[i], "--cpu-period") && i + 1 < end) {
			cpu->period_present = 1;
			cpu->period = std::stoi(argv[++i]);
			printf("%d\n", cpu->period);
		} else if(!strcmp(argv[i], "--cpu-quota") && i + 1 < end) {
			cpu->quota_present = 1;
			cpu->quota = std::stoi(argv[++i]);
			printf("%d\n", cpu->quota);
		} else {
			(*req)->image = argv[i];
			(*req)->container_id = argv[i];
		}
	}

	resources->memory = memory;
	resources->cpu = cpu;
	linux->resources = resources;
	container_spec->linux = linux;
	json_data = oci_runtime_spec_generate_json(container_spec, NULL, &err);
	if(json_data == NULL) {
		LOG_ERROR("get container_spec failed : %s", err ? err : "");
		ret = -1;
		goto clean_container_spec;
	}
	(*req)->container_spec = json_data;
	free(json_data);

clean_container_spec:
	free_oci_runtime_spec(container_spec);
	container_spec = NULL;
out:
	return ret;
}

int parse_command_parameters(struct command_parameter *cmd, int argc, char **argv) {
	int ret = 0;

	for(int i = 1; i < argc; i++) {
		if(strcmp(argv[i], "pull") == 0 && i + 1 < argc)	{
			cmd->action = strdup_s(argv[i]);
			cmd->image = strdup_s(argv[i+1]);
			break;
		}
		else if(strcmp(argv[i], "rmi") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			cmd->image = strdup_s(argv[i+1]);
			break;
		}
		else if(strcmp(argv[i], "create") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			docker::CreateRequest *req = (docker::CreateRequest*)calloc_s(1, sizeof(docker::CreateRequest));
			ret = parse_create_command(i + 1, argc, argv, &req);
			if(ret != 0) {
				LOG_ERROR("parse create command err!");
				ret = -1;
				break;
			}
			cmd->arg = (void*)req;
			break;
		}
		else if(strcmp(argv[i], "rm") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			cmd->container = strdup_s(argv[i+1]);
			break;
		}
		else if(strcmp(argv[i], "start") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			cmd->container = strdup_s(argv[i+1]);
			break;
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

void do_create_container(const docker::CreateRequest *req) {
	docker::container container;
	container.create(req);
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
			do_create_container((docker::CreateRequest*)(cmd->arg));
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
