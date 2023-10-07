#ifndef __DOCKER_H__
#define __DOCKER_H__

#include <sys/wait.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <grp.h>
#include <unistd.h>
#include <sched.h>
#include <cstring>
#include <string>
#include <net/if.h>
#include <arpa/inet.h>
#include <unordered_map>
#include "network.h"

#define STACK_SIZE (512 * 512)

namespace docker {

typedef struct container_config {
	std::string host_name;
	std::string root_dir;
	std::string ip;
	std::string bridge_name;
	std::string bridge_ip;
} container_config;

class ImageManager {
public:
	ImageManager();
	virtual ~ImageManager() {};
	
	std::string PullImage(const std::string image);
	void RemoveImage(const std::string image);
};

class container {
private:
	typedef int process_pid;
	char child_stack[STACK_SIZE];
	container_config config;
	char *veth1, *veth2;
	void basic_setting();
	void start_bash();
	void start_container();
	void set_hostname();
	void set_rootdir();
	void set_procsys();
	void set_network();
public:
	container(/*container_config &config*/);
	~container() {
		lxc_netdev_delete_by_name(veth1);
		lxc_netdev_delete_by_name(veth2);
	}
	void create(const std::string container_id, const std::string rootfs, const std::string image);
	void remove(const std::string container_id);
	void start(const std::string container_id);
};

}

#endif
