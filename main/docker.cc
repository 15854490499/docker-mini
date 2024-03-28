#include <iostream>
#include <libgen.h>

#include "docker.h"

#include "utils.h"
#include "image_api.h"
#include "container_api.h"
#include "oci_runtime_spec.h"
#include "log.h"

typedef int proc_status;

proc_status proc_wait = 0;
proc_status proc_error = -1;

docker::container::container() {
	int ret = 0;
	ret = oci_init();
	if(ret != 0) {
		LOG_ERROR("oci init err\n");
		exit(1);
	}
}

void docker::container::basic_setting() {
	setuid(0);
	setgid(0);
	setgroups(0, NULL);
}

void docker::container::start_bash() {
	std::string bash = "/bin/bash";
	char *c_bash = new char[bash.length() + 1];
	strcpy(c_bash, bash.c_str());
	char* const child_args[] = {c_bash, NULL};
	execv(child_args[0], child_args);
	delete[] c_bash;
}

static int remove_cgroup_dir(const char *id, const char *type);

void docker::container::start_container() {
	int ret = 0;
	char veth1buf[IFNAMSIZ] = "enp0s3X";
	char veth2buf[IFNAMSIZ] = "enp0s3X";
	process_pid child_pid;

	veth1 = lxc_mkifname(veth1buf);
	veth2 = lxc_mkifname(veth2buf);
	if(veth1 == NULL || veth2 == NULL) {
		LOG_ERROR("can not create ifname\n");
		return;
	}

	ret = lxc_veth_create(veth1, veth2);
	if(ret != 0) {
		LOG_ERROR("create veth pair err\n");
		goto out;
	}

	ret = setup_private_host_hw_addr(veth1);
	if(ret != 0) {
		LOG_ERROR("setup private host hardware addr err\n");
		goto out;
	}
	
	ret = lxc_bridge_attach(config.bridge_name.c_str(), veth1);
	if(ret != 0) {
		LOG_ERROR("attach veth1 to bridge err\n");
		goto out;
	}

	ret = lxc_netdev_up(veth1);
	if(ret != 0) {
		LOG_ERROR("setup veth1 err\n");
		goto out;
	}

	setup = [](void *args) -> int {
		auto _this = reinterpret_cast<container *>(args);
		_this->set_cgroup();
		_this->basic_setting();
		_this->set_hostname();
		_this->set_rootdir();
		_this->set_procsys();
		_this->set_network();
		_this->start_bash();
		return proc_wait;
	};

	if((m_sem = sem_open("/docker-mini", O_CREAT | O_RDWR, 0666, 0)) == SEM_FAILED) {
		LOG_ERROR("sem_open err\n");
		goto out;
	}
	LOG_INFO("%d", getpid());
	child_pid = clone(setup, child_stack, 
								CLONE_NEWPID|
								CLONE_NEWNS|
								CLONE_NEWUTS|
								CLONE_NEWNET|
								SIGCHLD, this);
	lxc_netdev_move_by_name(veth2, child_pid, "eth0");
	sem_post(m_sem);
	waitpid(child_pid, nullptr, 0);

	remove_cgroup_dir(config.container_id.c_str(), "memory");
	remove_cgroup_dir(config.container_id.c_str(), "cpu");
	lxc_netdev_delete_by_name(veth1);
	lxc_netdev_delete_by_name(veth2);
out:
	sem_close(m_sem);
	free(veth1);
	free(veth2);
	return;
}

void docker::container::set_hostname() {
	sethostname(this->config.host_name.c_str(), this->config.host_name.length());
}

void docker::container::set_rootdir() {
	chdir(this->config.root_dir.c_str());
	chroot(".");
}

void docker::container::set_procsys() {
	mount("none", "/proc", "proc", 0, nullptr);
	mount("none", "/sys", "sysfs", 0, nullptr);
}

void docker::container::set_network() {
	int ifindex = 0;
	struct in_addr ipv4;
	struct in_addr bcast;
	struct in_addr gateway;

	sem_wait(this->m_sem);
	ifindex = if_nametoindex("eth0");
	inet_pton(AF_INET, this->config.ip.c_str(), &ipv4);
	inet_pton(AF_INET, "255.255.255.0", &bcast);
	inet_pton(AF_INET, this->config.bridge_ip.c_str(), &gateway);
	lxc_ipv4_addr_add(ifindex, &ipv4, &bcast, 16);
	lxc_netdev_up("lo");
	lxc_netdev_up("eth0");
	lxc_ipv4_gateway_add(ifindex, &gateway);
	char mac[18];
	new_hwaddr(mac);
	setup_hw_addr(mac, "eth0");
}

static int remove_cgroup_dir(const char *id, const char *type) 
{
	int nret = 0;
    char cgroup_path[PATH_MAX] = { 0x00 };

	nret = snprintf(cgroup_path, sizeof(cgroup_path), "%s/%s/docker-mini/%s", CGROUP_ROOT, type, id);
	if(nret < 0 || nret >= sizeof(cgroup_path))  {
		LOG_ERROR("Failed to get memory cgroup path by id : %s", id);
		return -1;
	}
	
	if(!dir_exists(cgroup_path)) {
		return 0;
	}

    if(rmdir(cgroup_path) != 0) { 
    	LOG_ERROR("Failed to delete cgroup directory %s : %s", cgroup_path, strerror(errno));
        return -1;
    }    

    return 0;
}

void docker::container::set_cgroup() {
	int nret = 0;
	char spec_path[PATH_MAX] = { 0x00 };
	char cgroup_path[PATH_MAX];
	char cgroup_dir[PATH_MAX];
	char *id = NULL;
	parser_error err;
	oci_runtime_spec *container_spec = NULL;

	id = const_cast<char*>(this->config.container_id.c_str());
	nret = snprintf(spec_path, sizeof(spec_path), "%s/%s/%s", runtime_dir, id, RUNTIME_JSON);
	if(nret < 0 || nret >= sizeof(spec_path))  {
		LOG_ERROR("Failed to get runtime path by id : %s", id);
		return;
	}
	
	container_spec = oci_runtime_spec_parse_file(spec_path, NULL, &err);
	if(container_spec == NULL) {
		LOG_ERROR("Failed to parse the container_spec : %s", err);
		return;
	}

	if(container_spec->linux == NULL || container_spec->linux->resources == NULL) {
		LOG_ERROR("container_spec->linux == NULL");
		return;
	}
	
	if(container_spec->linux->resources->memory != NULL && container_spec->linux->resources->memory->limit > 0) {
		memset(cgroup_path, 0x00, PATH_MAX);
		nret = snprintf(cgroup_path, sizeof(cgroup_path), "%s/memory/docker-mini/%s/memory.limit_in_bytes", CGROUP_ROOT, id);
		if(nret < 0 || nret >= sizeof(cgroup_path))  {
			LOG_ERROR("Failed to get memory cgroup path by id : %s", id);
			goto out;
		}
		strcpy(cgroup_dir, cgroup_path);
		mkdir_p(dirname(cgroup_dir), 0700);
		std::string memory_limit = std::to_string(container_spec->linux->resources->memory->limit);
		if(write_file(cgroup_path, memory_limit.c_str(), memory_limit.size(), 0600) != 0) {
			LOG_ERROR("Failed to write to memory cgroup path %s", cgroup_path);
			goto clear_memory_dir;
		}
		memset(cgroup_path, 0x00, PATH_MAX);
		nret = snprintf(cgroup_path, sizeof(cgroup_path), "%s/memory/docker-mini/%s/tasks", CGROUP_ROOT, id);
		if(nret < 0 || nret >= sizeof(cgroup_path))  {
			LOG_ERROR("Failed to get memory cgroup path by id : %s", id);
			goto clear_memory_dir;
		}
		std::string pid_str = std::to_string(getpid());
		if(write_file(cgroup_path, pid_str.c_str(), pid_str.size(), 0600) != 0) {
			LOG_ERROR("Failed to write to memory cgroup path %s", cgroup_path);
			goto clear_memory_dir;
		}
	}
	if(container_spec->linux->resources->cpu != NULL) {
		if(container_spec->linux->resources->cpu->quota > 0 && container_spec->linux->resources->cpu->period > 0) {
			memset(cgroup_path, 0x00, PATH_MAX);
			nret = snprintf(cgroup_path, sizeof(cgroup_path), "%s/cpu/docker-mini/%s/cpu.cfs_quota_us", CGROUP_ROOT, id);
			if(nret < 0 || nret >= sizeof(cgroup_path))  {
				LOG_ERROR("Failed to get cpu cgroup path by id : %s", id);
				goto out;
			}
			strcpy(cgroup_dir, cgroup_path);
			mkdir_p(dirname(cgroup_dir), 0700);
			std::string cpu_quota = std::to_string(container_spec->linux->resources->cpu->quota);
			if(write_file(cgroup_path, cpu_quota.c_str(), cpu_quota.size(), 0600) != 0) {
				LOG_ERROR("Failed to write to cpu cgroup path %s", cgroup_path);
				goto clear_cpu_dir;
			}
			memset(cgroup_path, 0x00, PATH_MAX);
			nret = snprintf(cgroup_path, sizeof(cgroup_path), "%s/cpu/docker-mini/%s/cpu.cfs_period_us", CGROUP_ROOT, id);
			if(nret < 0 || nret >= sizeof(cgroup_path))  {
				LOG_ERROR("Failed to get cpu cgroup path by id : %s", id);
				goto clear_cpu_dir;
			}
			std::string cpu_period = std::to_string(container_spec->linux->resources->cpu->period);
			if(write_file(cgroup_path, cpu_period.c_str(), cpu_period.size(), 0600) != 0) {
				LOG_ERROR("Failed to write to cpu cgroup path %s", cgroup_path);
				goto clear_cpu_dir;
			}
			memset(cgroup_path, 0x00, PATH_MAX);
			nret = snprintf(cgroup_path, sizeof(cgroup_path), "%s/cpu/docker-mini/%s/tasks", CGROUP_ROOT, id);
			if(nret < 0 || nret >= sizeof(cgroup_path))  {
				LOG_ERROR("Failed to get memory cgroup path by id : %s", id);
				goto clear_cpu_dir;
			}
			std::string pid_str = std::to_string(getpid());
			if(write_file(cgroup_path, pid_str.c_str(), pid_str.size(), 0600) != 0) {
				LOG_ERROR("Failed to write to memory cgroup path %s", cgroup_path);
				goto clear_cpu_dir;
			}
		}
	}

	goto out;

clear_memory_dir:
	nret = remove_cgroup_dir(id, "memory");
	if(nret != 0) {
		LOG_ERROR("remove cgroup memory dir of %s failed, try to remove it force", id);
	}

clear_cpu_dir:
	nret = remove_cgroup_dir(id, "cpu");
	if(nret != 0) {
		LOG_ERROR("remove cgroup cpu dir of %s failed, try to remove it force", id);
	}

out:
	return;
}

void docker::container::start(const std::string container_id) {
	char *mount_point = NULL;
	std::cout << "...start container" << std::endl;
	container_config config;
	config.host_name = "test";
	mount_point = container_get_mount_point(container_id.c_str());
	if(mount_point == NULL) {
		return;
	}
	config.container_id = container_id;
	config.root_dir = mount_point;
	config.ip = "192.168.0.100";
	config.bridge_name = "docker-mini0";
	config.bridge_ip = "192.168.0.1";
	this->config = config;
	this->start_container();
	std::cout << "stop container..." << std::endl;
	free(mount_point);
	container_umount_point(container_id.c_str());
}
