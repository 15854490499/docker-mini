#include <iostream>
#include <string.h>

#include "grpc_connect.h"
#include "oci_runtime_spec.h"
#include "parse_cmd.h"
#include "utils.h"

void command_parameters_init(struct command_parameter **cmd) {
	*cmd = (struct command_parameter*)common_calloc_s(sizeof(struct command_parameter));
	
	(*cmd)->action = NULL;
}

void free_command_parameters(struct command_parameter *cmd) {
	if(cmd == NULL) {
		return;
	}

	if(cmd->action) {
		free(cmd->action);
	}

	//free(cmd->arg);

	free(cmd);
}

static int parse_pull_command(int start, int end, char **argv, im_pull_request **req) {
	(*req)->image = strdup_s(argv[start]);

	return 0;
}

static int parse_rmi_command(int start, int end, char **argv, im_remove_request **req) {
	(*req)->image = strdup_s(argv[start]);

	return 0;
}

static int parse_create_command(int start, int end, char **argv, container_create_request **req) {
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
		printf("memory out");
		ret = -1;
		goto clean_container_spec;
	}

	container_spec->oci_version = strdup_s("0");

	linux = (oci_runtime_config_linux*)calloc_s(1, sizeof(oci_runtime_config_linux));
	if(linux == NULL) {
		printf("memory out");
		ret = -1;
		goto clean_container_spec;
	}
	
	resources = (oci_runtime_config_linux_resources*)calloc_s(1, sizeof(oci_runtime_config_linux_resources));
	if(resources == NULL) {
		printf("memory out");
		ret = -1;
		goto clean_container_spec;
	}

	memory = (oci_runtime_config_linux_resources_memory*)calloc_s(1, sizeof(oci_runtime_config_linux_resources_memory));
	if(memory == NULL) {
		printf("memory out");
		ret = -1;
		goto clean_container_spec;
	}

	cpu = (oci_runtime_config_linux_resources_cpu*)calloc_s(1, sizeof(oci_runtime_config_linux_resources_cpu));
	if(cpu == NULL) {
		printf("memory out");
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
			(*req)->image = strdup_s(argv[i]);
			(*req)->id = strdup_s(argv[i]);
		}
	}

	resources->memory = memory;
	resources->cpu = cpu;
	linux->resources = resources;
	container_spec->linux = linux;
	json_data = oci_runtime_spec_generate_json(container_spec, NULL, &err);
	if(json_data == NULL) {
		printf("get container_spec failed : %s", err ? err : "");
		ret = -1;
		goto clean_container_spec;
	}
	(*req)->container_spec = json_data;
	//free(json_data);

clean_container_spec:
	free_oci_runtime_spec(container_spec);
	container_spec = NULL;
out:
	return ret;
}

static int parse_rmc_command(int start, int end, char **argv, container_remove_request **req) {
	(*req)->id = strdup_s(argv[start]);

	return 0;
}

static int parse_start_command(int start, int end, char **argv, container_start_request **req) {
	(*req)->id = strdup_s(argv[start]);

	return 0;
}

int parse_command_parameters(struct command_parameter *cmd, int argc, char **argv) {
	int ret = 0;

	for(int i = 1; i < argc; i++) {
		if(strcmp(argv[i], "pull") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			im_pull_request *req = (im_pull_request*)calloc_s(1, sizeof(im_pull_request));
			ret = parse_pull_command(i + 1, argc, argv, &req);
			if(ret != 0) {
				printf("parse pull command err!\n");
				ret = -1;
				break;
			}
			cmd->arg = (void*)req;
			break;
		}
		else if(strcmp(argv[i], "rmi") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			im_remove_request *req = (im_remove_request*)calloc_s(1, sizeof(im_remove_request));
			ret = parse_rmi_command(i + 1, argc, argv, &req);
			if(ret != 0) {
				printf("parse rmi command err!\n");
				ret = -1;
				break;
			}
			cmd->arg = (void*)req;
			break;
		}
		else if(strcmp(argv[i], "create") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			container_create_request *req = (container_create_request*)calloc_s(1, sizeof(container_create_request));
			ret = parse_create_command(i + 1, argc, argv, &req);
			if(ret != 0) {
				printf("parse create command err!\n");
				ret = -1;
				break;
			}
			cmd->arg = (void*)req;
			break;
		}
		else if(strcmp(argv[i], "rm") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			container_remove_request *req = (container_remove_request*)calloc_s(1, sizeof(container_remove_request));
			ret = parse_rmc_command(i + 1, argc, argv, &req);
			if(ret != 0) {
				printf("parse rmc command err!\n");
				ret = -1;
				break;
			}
			cmd->arg = (void*)req;
			break;
		}
		else if(strcmp(argv[i], "start") == 0 && i + 1 < argc) {
			cmd->action = strdup_s(argv[i]);
			container_start_request *req = (container_start_request*)calloc_s(1, sizeof(container_start_request));
			if(ret != 0) {
				printf("parse start command err!\n");
				ret = -1;
				break;
			}
			cmd->arg = (void*)req;
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

int do_pull_image(im_pull_request *req) {
	int ret = 0;
	im_pull_response *resp { nullptr };
	grpc_connect_ops *ops { nullptr };
	
	client_connect_config config = get_connect_config();
	resp = (im_pull_response*)common_calloc_s(sizeof(im_pull_response));
	if(resp == NULL) {
		printf("memory out\n");
		ret = -1;
		goto out;
	}
	
	ops = get_grpc_connect_ops();
	if(ops == NULL || ops == nullptr) {
		printf("invalid NULL ptr\n");
		ret = -1;
		goto out;
	}

	ret = ops->image.pull(req, resp, &config);
	if(ret != 0) {
		printf("pull image failed\n");
		goto out;
	}
out:
	free_connect_config(&config);
	if(resp != NULL && resp->errmsg != NULL) {
		printf("%s\n", resp->errmsg);
	} else if(resp != NULL){
		printf("pulled %s\n", resp->image_ref);
	}
	free_im_pull_request(req);
	free_im_pull_response(resp);
	return ret;
}

int do_remove_image(im_remove_request *req) {
	int ret = 0;
	im_remove_response *resp { nullptr };
	grpc_connect_ops *ops { nullptr };
	
	client_connect_config config = get_connect_config();
	resp = (im_remove_response*)common_calloc_s(sizeof(im_remove_response));
	if(resp == NULL) {
		printf("memory out\n");
		ret = -1;
		goto out;
	}
	
	ops = get_grpc_connect_ops();
	if(ops == NULL || ops == nullptr) {
		printf("invalid NULL ptr\n");
		ret = -1;
		goto out;
	}
	ret = ops->image.remove(req, resp, &config);
	if(ret != 0) {
		printf("remove image failed\n");
		goto out;
	}
out:
	free_connect_config(&config);
	if(resp != NULL && resp->errmsg != NULL) {
		printf("%s\n", resp->errmsg);
	} else if(resp != NULL) {
		printf("removed image %s\n", req->image);
	}
	free_im_remove_request(req);
	free_im_remove_response(resp);
	return ret;
}

int do_create_container(container_create_request *req) {
	int ret = 0;
	container_create_response *resp { nullptr };
	grpc_connect_ops *ops { nullptr };

	client_connect_config config = get_connect_config();
	resp = (container_create_response*)common_calloc_s(sizeof(container_create_response));
	if(resp == NULL) {
		printf("memory out\n");
		ret = -1;
		goto out;
	}
	
	ops = get_grpc_connect_ops();
	if(ops == NULL || ops == nullptr) {
		printf("invalid NULL ptr\n");
		ret = -1;
		goto out;
	}

	ret = ops->container.create(req, resp, &config);
	if(ret != 0) {
		printf("create container failed\n");
	}

out:
	free_connect_config(&config);
	if(resp != NULL && resp->errmsg != NULL) {
		printf("%s\n", resp->errmsg);
	} else if(resp != NULL) {
		printf("created %s\n", resp->id);
	}
	free_container_create_request(req);
	free_container_create_response(resp);
	
	return ret;
}

int do_remove_container(container_remove_request *req) {
	int ret = 0;
	container_remove_response *resp { nullptr };
	grpc_connect_ops *ops { nullptr };

	client_connect_config config = get_connect_config();
	resp = (container_remove_response*)common_calloc_s(sizeof(container_remove_response));
	if(resp == NULL) {
		printf("memory out\n");
		ret = -1;
		goto out;
	}
	
	ops = get_grpc_connect_ops();
	if(ops == NULL || ops == nullptr) {
		printf("invalid NULL ptr\n");
		ret = -1;
		goto out;
	}

	ret = ops->container.remove(req, resp, &config);
	if(ret != 0) {
		printf("remove container failed\n");
	}
out:
	free_connect_config(&config);
	if(resp != NULL && resp->errmsg != NULL) {
		printf("%s\n", resp->errmsg);
	} else if(resp != NULL) {
		printf("remove container %s\n", resp->id);
	}

	free_container_remove_request(req);
	free_container_remove_response(resp);
	return ret;
}

int do_start_container(container_start_request *req) {
	int ret = 0;
	container_start_response *resp { nullptr };
	grpc_connect_ops *ops { nullptr };

	client_connect_config config = get_connect_config();
	resp = (container_start_response*)common_calloc_s(sizeof(container_start_response));
	if(resp == NULL) {
		printf("memory out\n");
		ret = -1;
		goto out;
	}
	
	ops = get_grpc_connect_ops();
	if(ops == NULL || ops == nullptr) {
		printf("invalid NULL ptr\n");
		ret = -1;
		goto out;
	}

	ret = ops->container.start(req, resp, &config);
	if(ret != 0) {
		printf("start container failed\n");
	}

out:
	free_connect_config(&config);
	if(resp != NULL && resp->errmsg != NULL) {
		printf("%s\n", resp->errmsg);
	}
	free_container_start_request(req);
	free_container_start_response(resp);
	return ret;
}

int execute_command(struct command_parameter *cmd) {
	int ret = 0;
	
	ret = grpc_connect_ops_init();
	if(ret != 0) {
		printf("grpc int err\n");
		return -1;
	}

	if(cmd->action) {
		if(strcmp(cmd->action, "pull") == 0) {
			ret = do_pull_image((im_pull_request*)(cmd->arg));
		}
		else if(strcmp(cmd->action, "rmi") == 0) {
			ret = do_remove_image((im_remove_request*)(cmd->arg));
		}
		else if(strcmp(cmd->action, "create") == 0) {
			ret = do_create_container((container_create_request*)(cmd->arg));
		}
		else if(strcmp(cmd->action, "rm") == 0) {
			ret = do_remove_container((container_remove_request*)(cmd->arg));
		}
		else if(strcmp(cmd->action, "start") == 0) {
			ret = do_start_container((container_start_request*)(cmd->arg));
		}
	}
		
	return ret;
}
