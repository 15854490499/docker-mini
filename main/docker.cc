#include <iostream>

#include "docker.h"

#include "utils.h"
#include "image_api.h"
#include "container_api.h"
#include "log.h"

typedef int proc_status;

proc_status proc_wait = 0;
proc_status proc_error = -1;

docker::ImageManager::ImageManager() {
	int ret = 0;
	ret = oci_init();
	if(ret != 0) {
		LOG_ERROR("oci init err\n");
		exit(1);
	}
}

std::string docker::ImageManager::PullImage(const std::string image) {
	int ret = 0;
	std::string out_str = "";
	im_pull_request *request { nullptr };
	im_pull_response *response { nullptr };
	
	request = (im_pull_request*)common_calloc_s(sizeof(im_pull_request));
	if(request == nullptr) {
		LOG_ERROR("Out of memory\n");
		goto cleanup;
	}
	request->type = strdup_s(IMAGE_TYPE_OCI);
	request->image = strdup_s(const_cast<char*>(image.c_str()));

	ret = im_pull_image(request, &response);
	if(ret != 0) {
		if(response != nullptr && response->errmsg != nullptr) {
			LOG_ERROR("%s\n", response->errmsg);
		} else {
			LOG_ERROR("Failed to call pull image\n");
		}
		goto cleanup;
	}
	if(response->image_ref != nullptr) {
		out_str = response->image_ref;
	}
cleanup:
	free_im_pull_request(request);
	free_im_pull_response(response);
	return out_str;
}

void docker::ImageManager::RemoveImage(const std::string image) {
	int ret = 0;
	im_rmi_request *request { nullptr };
	im_remove_response *response { nullptr };
	
	request = (im_rmi_request*)common_calloc_s(sizeof(im_rmi_request));
	if(request == nullptr) {
		LOG_ERROR("Out of memory\n");
		goto cleanup;
	}
	request->image = strdup_s(image.c_str());
	request->force = false;

	ret = im_rm_image(request, &response);
	if(ret != 0) {
		LOG_ERROR("%s\n", response->errmsg);
		goto cleanup;
	}

cleanup:
	free_im_rmi_request(request);
	free_im_remove_response(response);
	return;
}

docker::container::container(/*container_config &config*/) {
	//this->config = config;
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

	child_pid = clone(setup, child_stack, 
								CLONE_NEWPID|
								CLONE_NEWNS|
								CLONE_NEWUTS|
								CLONE_NEWNET|
								SIGCHLD, this);
	lxc_netdev_move_by_name(veth2, child_pid, "eth0");
	sem_post(m_sem);
	waitpid(child_pid, nullptr, 0);

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

void docker::container::create(const std::string container_id, const std::string rootfs, const std::string image) {
	int ret = 0;
	container_create_request *request { nullptr };
	container_create_response *response { nullptr };

	request = (container_create_request*)common_calloc_s(sizeof(container_create_request));
		
	if(container_id != "") {
		request->id = (char*)strdup_s(const_cast<char*>(container_id.c_str()));
	} else {
		request->id = NULL; 
	}
	if(image != "") {
		request->image = (char*)strdup_s(const_cast<char*>(image.c_str()));
	} else {
		request->image = NULL;
	}
	if(rootfs != "") {
		request->rootfs = (char*)strdup_s(const_cast<char*>(rootfs.c_str()));
	} else {
		request->rootfs = NULL;
	}

	ret = container_create(request, &response);

	if(response->errmsg != NULL) {
		LOG_ERROR("%s\n", response->errmsg);		
	}
	
	free_container_create_request(request);
	free_container_create_response(response);
}

void docker::container::remove(const std::string container_id) {
	int ret = 0;
	container_delete_request *request { nullptr };
	container_delete_response *response { nullptr };

	request = (container_delete_request*)common_calloc_s(sizeof(container_delete_request));

	request->id = (char*)strdup_s(const_cast<char*>(container_id.c_str()));
	
	ret = container_delete(request, &response);

	if(response->errmsg != NULL) {
		LOG_ERROR("%s\n", response->errmsg);
	}

	free_container_delete_request(request);
	free_container_delete_response(response);
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
	config.root_dir = mount_point;
	config.ip = "192.168.0.100";
	config.bridge_name = "docker-mini0";
	config.bridge_ip = "192.168.0.1";
	this->config = config;
	this->start_container();
	std::cout << "stop container..." << std::endl;
	container_umount_point(container_id.c_str());
}
