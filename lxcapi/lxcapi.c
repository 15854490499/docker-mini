#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <lxc/lxccontainer.h>

#include "log.h"
#include "lxcapi.h"

static int create_partial(const struct lxc_container *c)
{
    int fd = 0; 
    int ret = 0; 
    struct flock lk;
    char path[PATH_MAX] = { 0 }; 

    ret = snprintf(path, PATH_MAX, "%s/%s/partial", c->config_path, c->name);
    if (ret < 0 || (size_t)ret >= PATH_MAX) {
        LOG_ERROR("Error writing partial pathname");
        return -1;
    }    

    fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0666);
    if (fd < 0) { 
        LOG_ERROR("Error creating partial file: %s", path);
        return -1;
    }    
    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = 0; 
    lk.l_len = 0; 
    if (fcntl(fd, F_SETLKW, &lk) < 0) { 
        LOG_ERROR("Error locking partial file %s", path);
        close(fd);
        return -1;
    }    

    return fd;
}

static int remove_partial(const struct lxc_container *c) {
	int ret = 0;
	char path[PATH_MAX] = { 0 }; 

    ret = snprintf(path, PATH_MAX, "%s/%s/partial", c->config_path, c->name);
    if (ret < 0 || (size_t)ret >= PATH_MAX) {
        LOG_ERROR("Error writing partial pathname");
        return -1;
    }
	
	ret = path_remove(path);
	if(ret != 0) {
		LOG_ERROR("Failed to remove file %s", path);
		return -1;
	}

	return 0;
}

static struct lxc_params_list *create_lxc_list_node(const char *k, const char *v) {
	struct lxc_params_list *node = NULL;
	char *dst = NULL;
	char sep[1] = " ";
	const char *parts[3] = {k, "=", v};

	node = common_calloc_s(sizeof(struct lxc_params_list));
	if(node == NULL) {
		LOG_ERROR("memory out\n");
		return NULL;
	}
	lxc_params_list_init(node);

	dst = string_join(sep, parts, 3);
	if(dst == NULL) {
		LOG_ERROR("join %s and %s err", k, v);
		goto err_out;
	}
	node->data = dst;
	
	goto out;

err_out:
	free(node);
	node = NULL;
out:
	return node;
}

static void lxc_free_config(struct lxc_params_list *conf) {
	struct lxc_params_list *idx = conf;
	struct lxc_params_list *tmp = NULL;
	
	conf->prev->next = NULL;

	while(idx != NULL) {
		tmp = idx->next;
		free(idx->data);
		idx->data = NULL;
		free(idx);
		idx = tmp;
	}

	conf = NULL;
	
	return;
}

static struct lxc_params_list *trans_oci_root(const oci_runtime_spec_root *root) {
	struct lxc_params_list *conf = NULL;
	struct lxc_params_list *tmp_node = NULL;

	conf = common_calloc_s(sizeof(struct lxc_params_list));
	if(conf == NULL) {
		LOG_ERROR("memory out\n");
		return NULL;
	}
	lxc_params_list_init(conf);

	if(root != NULL && root->path != NULL) {
		if(strcmp(root->path, "/") != 0) {
			tmp_node = create_lxc_list_node("lxc.rootfs.path", root->path);
			if(tmp_node == NULL) {
				LOG_ERROR("create lxc node err");
				goto err_out;
			}
			lxc_list_add(conf, tmp_node);
		}

		if(root->readonly) {
			tmp_node = create_lxc_list_node("lxc.rootfs.options", "ro");
			if(tmp_node == NULL) {
				LOG_ERROR("create lxc node err");
				goto err_out;
			}
			lxc_list_add(conf, tmp_node);
		}
	}

	goto out;
err_out:
	lxc_free_config(conf);
	conf = NULL;
out:
	return conf;
}

static int trans_oci_hostname(struct lxc_params_list *lxc_conf, const char *hostname) {
	int ret = 0;
	struct lxc_params_list *tmp = NULL;

	tmp = create_lxc_list_node("lxc.uts.name", hostname);
	if(tmp == NULL) {
		LOG_ERROR("failed to create lxc.uts.name");
		return -1;
	}
	lxc_list_merge(lxc_conf, tmp);

	return 0;
}

static int trans_conf_int2str(struct lxc_params_list *conf, const char *lxc_key, int64_t val) {
	int ret = 0;
	struct lxc_params_list *node = NULL;
	char buf_value[DEFAULT_BUF_LEN] = { 0x00 };
	
	ret = snprintf(buf_value, sizeof(buf_value), "%lld", (long long)val);
	if(ret < 0 || ret >= sizeof(buf_value)) {
		LOG_ERROR("snprintf err");
		return -1;
	}

	node = create_lxc_list_node(lxc_key, buf_value);
	if(node == NULL) {
		return -1;
	}
	lxc_list_add(conf, node);
	return 0;
}

static int trans_resources_memory(const oci_runtime_config_linux_resources *res, struct lxc_params_list *conf) {

	if(res->memory == NULL) {
		return 0;
	}

	if(res->memory->limit > 0) {
		if(trans_conf_int2str(conf, "lxc.cgroup2.memory.max", res->memory->limit) != 0) {
			return -1;
		}
	}

	return 0;
}

static int trans_resources_cpu(const oci_runtime_config_linux_resources *res, struct lxc_params_list *conf) {
	char buf_value[DEFAULT_BUF_LEN] = { 0x00 };
	uint64_t period = res->cpu->period;
	int64_t quota = res->cpu->quota;
	struct lxc_params_list *node = NULL;
	int nret = 0;

	if(quota == 0 && period == 0) {
		return 0;
	}

	if(period == 0) {
		period = DEFAULT_CPU_PERIOD;
	}

	if(quota > 0) {
		nret = snprintf(buf_value, sizeof(buf_value), "%lld %llu", (long long)quota, (unsigned long long)period);
	} else {
		nret = snprintf(buf_value, sizeof(buf_value), "max %llu", (unsigned long long)period);
	}
	if(nret < 0 || nret >= sizeof(buf_value)) {
		LOG_ERROR("failed to printf cpu max");
		return -1;
	}
	
	node = create_lxc_list_node("lxc.cgroup2.cpu.max", buf_value);
	if(node == NULL) {
		return -1;
	}
	lxc_list_add(conf, node);

	return 0;
}

static struct lxc_params_list *trans_oci_resources(const oci_runtime_config_linux_resources *res) {
	struct lxc_params_list *conf = NULL;

	conf = common_calloc_s(sizeof(struct lxc_params_list));
	if(conf == NULL) {
		return NULL;
	}
	lxc_params_list_init(conf);

	if(trans_resources_memory(res, conf) != 0) {
		goto err_out;
	}
	
	if(trans_resources_cpu(res, conf) != 0) {
		goto err_out;
	}
	
	goto out;
err_out:
	lxc_free_config(conf);
	conf = NULL;
out:
	return conf;
}

static struct lxc_params_list *trans_oci_linux(const oci_runtime_config_linux *l) {
	int ret = 0;
	struct lxc_params_list *tmp = NULL;

	struct lxc_params_list *conf = common_calloc_s(sizeof(struct lxc_params_list));
	if(conf == NULL) {
		return NULL;
	}
	lxc_params_list_init(conf);

	if(l->resources != NULL) {
		tmp = trans_oci_resources(l->resources);
		if(tmp == NULL) {
			goto err_out;
		}
		lxc_list_merge(conf, tmp);
	}

	goto out;
err_out:
	lxc_free_config(conf);
	conf = NULL;
out:
	return conf;
}

static int trans_rootfs_linux(struct lxc_params_list *lxc_conf, oci_runtime_spec *container) {
	int ret = 0;
	struct lxc_params_list *node = NULL;

	if(container->root != NULL) {
		node = trans_oci_root(container->root);
		if(node == NULL) {
			LOG_ERROR("Failed to translate rootfs configure");
			ret = -1;
			goto out;
		}
		lxc_list_merge(lxc_conf, node);
	}

	if(container->linux != NULL) {
		node = trans_oci_linux(container->linux);
		if(node == NULL) {
			LOG_ERROR("Failed to translate linux configure");
			ret = -1;
			goto out;
		}
		lxc_list_merge(lxc_conf, node);
	}
out:
	return ret;
}

static int add_lxc_include(struct lxc_params_list *lxc_conf) {
	int ret = 0;
	struct lxc_params_list *node = NULL;

	node = create_lxc_list_node("lxc.include", COMMON_CONFIG);
	if(node == NULL) {
		ret = -1;
		goto out;
	}
	lxc_list_merge(lxc_conf, node);
	
out:
	return ret;
}

static FILE *lxc_open_config_file(const char *bundle)
{
    char config[PATH_MAX] = { 0 }; 
    char *real_config = NULL;
    int fd = -1;
    int nret = 0;
    FILE *fp = NULL;

    nret = snprintf(config, sizeof(config), "%s/config", bundle);
    if (nret < 0 || (size_t)nret >= sizeof(config)) {
        goto out; 
    }    

    fd = open(config, O_CREAT | O_TRUNC | O_CLOEXEC | O_WRONLY, 0666);
    if (fd == -1) {
        LOG_ERROR("Create file %s failed, %s", config, strerror(errno));
        goto out; 
    }    

    fp = fdopen(fd, "w");
    if(fp == NULL){
        LOG_ERROR("FILE open failed");
        goto out; 
    }    

out:
    return fp;
}

static int save_lxc_config(const char *id, struct lxc_params_list *lxc_conf) {
	int ret = 0;
	int nret = 0;
	char bundle[PATH_MAX] = { 0x00 };
	struct lxc_params_list *it = NULL;
	char *line = NULL;
	char *line_fin = NULL;
	int len = 0;
    FILE *fp = NULL;

	nret = snprintf(bundle, sizeof(bundle), "%s/%s", runtime_dir, id);
	if(nret < 0 || nret >= sizeof(bundle)) {
		LOG_ERROR("Failed to get runtime path by id : %s", id);
		return -1;
	}

	fp = lxc_open_config_file(bundle);
	if(fp == NULL) {
		return -1;
	}
	
	lxc_list_for_each(it, lxc_conf) {
		if(it->data != NULL) {
			line = (char*)(it->data);
			len = strlen(line);
			line_fin = common_calloc_s(len + 1);
			if(line_fin == NULL) {
				LOG_ERROR("memory out");
				goto err_out;
			}
			memcpy(line_fin, line, len);
			line_fin[len] = '\n';
			if(fwrite(line_fin, 1, len + 1, fp) != len + 1) {
				LOG_ERROR("Write file failed : %s", strerror(errno));
				goto err_out;
			}
			free(line_fin);
			line_fin = NULL;
		}
	}

	goto out;

err_out:
	ret = -1;
out:
	if(fp != NULL) {
		fclose(fp);
	}
	return ret;
}

static int create_lxc_spec(const char *id, oci_runtime_spec *oci_spec) {
	int ret = 0;
	struct lxc_params_list *lxc_conf = NULL;

	lxc_conf = common_calloc_s(sizeof(struct lxc_params_list));
	if(lxc_conf == NULL) {
		LOG_ERROR("memory out\n");
		return -1;
	}
	lxc_params_list_init(lxc_conf);

	ret = add_lxc_include(lxc_conf);
	if(ret != 0) {
		LOG_ERROR("Failed to add lxc include entry");
		ret = -1;
		goto out;
	}

	ret = trans_rootfs_linux(lxc_conf, oci_spec);
	if(ret != 0) {
		LOG_ERROR("Failed to translate rootfs linux");
		ret = -1;
		goto out;
	}
	
	ret = trans_oci_hostname(lxc_conf, oci_spec->hostname);
	if(ret != 0) {
		LOG_ERROR("Failed to translate hostname");
		ret = -1;
		goto out;
	}

	ret = save_lxc_config(id, lxc_conf);
	if(ret != 0) {
		LOG_ERROR("Failed to save lxc config file");
		ret = -1;
		goto out;
	}

out:
	lxc_free_config(lxc_conf);
	return ret;
}

int runtime_create(const char *id, oci_runtime_spec *container_spec) {
	int ret = 0;
	struct lxc_container *c = NULL;
	int partial_fd = -1;

	c = lxc_container_new(id, runtime_dir);
	if(c == NULL) {
		LOG_ERROR("new lxc container failed\n");
		return -1;
	}
	
	partial_fd = create_partial(c);
	if(partial_fd < 0) {
		lxc_container_put(c);
		return -1;
	}
	
	ret = create_lxc_spec(id, container_spec);
	if(ret != 0) {
		LOG_ERROR("create lxc spec failed");
		ret = -1;
		c->destroy(c);
		goto out;
	}

out:
	if(partial_fd >= 0) {
		close(partial_fd);
		remove_partial(c);
	}
	lxc_container_put(c);
	return ret;
}

static void execute_lxc_start(struct lxc_start_request *request) {
	char **params = { NULL };
	int nret = 0;
	char buf[PATH_MAX] = { 0x00 };

	array_append(&params, "lxc-start");
	array_append(&params, "-n");
	array_append(&params, request->name);
	array_append(&params, "-P");
	array_append(&params, request->path);
	array_append(&params, "--quiet");
	array_append(&params, "--logfile");
	array_append(&params, request->logpath);
	array_append(&params, "-l");
	array_append(&params, request->loglevel);
	
	if(request->daemonize) {
		array_append(&params, "-d");
	}
	array_append(&params, LXC_DEFAULT_START_COMMAND);
	/*if(request->image_type_oci) {
		nret = snprintf(buf, sizeof(buf), "%s=true", LXC_IMAGE_OCI_KEY);
		array_append(&params, "-s");
		array_append(&params, buf);
	}*/

	/*if(request->start_timeout > 0) {
		char start_timeout_str[PATH_MAX] = { 0x00 };
		array_append(&params, "--start-timeout");
		int num = snprintf(start_timeout_str, PATH_MAX, "%u", request->start_timeout);
		if(num < 0 || num >= PATH_MAX) {
			LOG_ERROR("invalid start timeout %u", request->start_timeout);
			exit(EXIT_FAILURE);
		}
		array_append(&params, start_timeout_str);
	}*/
	execvp("lxc-start", params);
	
	LOG_ERROR("Failed to exec lxc-start: %s", strerror(errno));
	free_array_by_len(params, array_len(params));
	exit(EXIT_FAILURE);
}

static int check_container_running(struct lxc_container *c, const char *name) {
    if (!c->is_defined(c)) {
        LOG_ERROR("No such container");
        return -1;
    }

    if (!c->may_control(c)) {
        LOG_ERROR("Insufficent privileges to control");
        return -1;
    }

    if (!c->is_running(c)) {
        LOG_ERROR("Container is not running");
        return -1;
    }
    return 0;
}

static int lxc_kill(const char *name, const char *lxcpath, uint32_t signal) {
    struct lxc_container *c = NULL;
    bool ret = false;
    int sret = 0; 
    pid_t pid = 0; 

    c = lxc_container_new(name, lxcpath);
    if (c == NULL) {
        LOG_ERROR("Failed to stop container.");
        return -1;
    }    

    if (check_container_running(c, name) != 0) {
        goto out_put;
    }    

    pid = c->init_pid(c);
    if (pid < 0) { 
        LOG_ERROR("Failed to get init pid");
        goto out_put;
    }    

    sret = kill(pid, (int)signal);
    if (sret < 0) { 
        if (errno == ESRCH) {
            LOG_WARN("Can not kill process (pid=%d) with signal %d for container: no such process", pid, signal);
            ret = 0;
            goto out_put;
        }
        LOG_ERROR("Can not kill process (pid=%d) with signal %d for container", pid, signal);
        goto out_put;
    }

    ret = 0;

out_put:
    lxc_container_put(c);
    return ret;
}

static int wait_start_pid(pid_t pid, int rfd, const char *name, const char *path) {
    int ret; 
    ssize_t size_read = 0; 
    char buffer[BUFSIZ] = { 0 }; 

    ret = wait_for_pid(pid);
    if (ret == 0) { 
        return 0;
    }    

    LOG_ERROR("Start container failed : %s\n", strerror(errno));

    LOG_INFO("begin to stop container\n");
    if (!lxc_kill(name, path, SIGKILL)) {
        LOG_ERROR("Failed to stop container");
    }    

    size_read = read(rfd, buffer, sizeof(buffer) - 1);
    if (size_read > 0) { 
        LOG_ERROR("Runtime error: %s", buffer);
    }    
    return -1;
}

int runtime_start(const char *id, const char *config_path) {
	int ret = 0;
	int nret = 0;
	int pipefd[2] = { -1, -1 };
	pid_t pid = 0;
	char path[PATH_MAX] = { 0x00 };
	char logpath[PATH_MAX] = { 0x00 };
	struct lxc_start_request request = { 0x00 };

	nret = snprintf(path, sizeof(path), "%s/config", config_path);
	if(nret < 0 || nret >= sizeof(path)) {
		LOG_ERROR("Failed to get runtime config for %s", id);
		return -1;
	}
	
	nret = snprintf(logpath, sizeof(logpath), "%s/log", config_path);
	if(nret < 0 || nret >= sizeof(logpath)) {
		LOG_ERROR("Failed to get runtime log path for %s", id);
		return -1;
	}

	if(!file_exists(path)) {
		LOG_ERROR("%s not exists", path);
		return -1;
	}

	if(pipe(pipefd) != 0) {
		LOG_ERROR("Failed to create pipe");
		return -1;
	}
	
	request.name = strdup_s(id);
	request.path = strdup_s(runtime_dir);
	request.logpath = strdup_s(logpath);
	request.loglevel = strdup_s(DEFAULT_LOGLEVEL);
	request.start_timeout = DEFAULT_TIMEOUT;
	request.daemonize = true;
	request.image_type_oci = true;

	pid = fork();
	if(pid == -1) {
		LOG_ERROR("Failed to fork()");
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if(pid == 0) {
		unsetenv("NOTIFY_SOCKET");
		close(pipefd[0]);
		dup2(pipefd[1], 2);
		execute_lxc_start(&request);
	}
	close(pipefd[1]);
	ret = wait_start_pid(pid, pipefd[0], id, path);
	close(pipefd[0]);
	return 0;
}

static void execute_lxc_attach(const struct lxc_attach_request *request) {
	char **params = { NULL };
	
	array_append(&params, "lxc-attach");
	array_append(&params, "-n");
	array_append(&params, request->name);
	array_append(&params, "-P");
	array_append(&params, request->path);
	array_append(&params, "--clear-env");
	array_append(&params, "--quiet");
	array_append(&params, "--logfile");
	array_append(&params, request->logpath);
	array_append(&params, "-l");
	array_append(&params, request->loglevel);
	
	execvp("lxc-attach", params);

	LOG_ERROR("Failed to exec lxc-attach: %s", strerror(errno));
	free_array_by_len(params, array_len(params));
	//exit(EXIT_FAILURE);
}

int runtime_attach(const char *id, const char *config_path) {
	int ret = 0;
	int nret = 0;
	char logpath[PATH_MAX] = { 0x00 };
    struct lxc_container *c = NULL;
	struct lxc_attach_request request = { 0x00 };

	nret = snprintf(logpath, sizeof(logpath), "%s/log", config_path);
	if(nret < 0 || nret >= sizeof(logpath)) {
		LOG_ERROR("Failed to get runtime log path for %s", id);
		return -1;
	}

	c = lxc_container_new(id, runtime_dir);
	if(c == NULL) {
		LOG_ERROR("Failed to delete container");
		goto out;
	}

	if(check_container_running(c, id) != 0) {
        goto out_put;
    }

	lxc_container_put(c);

	request.name = strdup_s(id);
	request.path = strdup_s(runtime_dir);
	request.logpath = strdup_s(logpath);
	request.loglevel = strdup_s(DEFAULT_LOGLEVEL);

	execute_lxc_attach(&request);
	
	goto out;

out_put:
	lxc_container_put(c);

out:
	return ret;
}

int runtime_stop(const char *id) {
	int ret = 0;
    struct lxc_container *c = NULL;

	c = lxc_container_new(id, runtime_dir);
	if(c == NULL) {
		LOG_ERROR("Failed to delete container");
		goto out;
	}

	if(check_container_running(c, id) != 0) {
        goto out_put;
    }
	
	ret = c->stop(c);
	if(ret == 0) {
		LOG_ERROR("Eexecute stop error");
		ret = -1;
	}

	ret = 0;
out_put:
	lxc_container_put(c);

out:
	return ret;
}
