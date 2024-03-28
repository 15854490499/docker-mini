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
#include <semaphore.h>

#include "network.h"

#define STACK_SIZE (512 * 512)

namespace docker {

typedef struct container_config {
	std::string container_id;
	std::string host_name;
	std::string root_dir;
	std::string ip;
	std::string bridge_name;
	std::string bridge_ip;
} container_config;

class container {
private:
	typedef int process_pid;
	char child_stack[STACK_SIZE];
	container_config config;
	char *veth1, *veth2;
	sem_t *m_sem;
	int (*setup)(void *);
	void basic_setting();
	void start_bash();
	void start_container();
	void set_hostname();
	void set_rootdir();
	void set_procsys();
	void set_network();
	void set_cgroup();
public:
	container(/*container_config &config*/);
	~container() { }
	void start(const std::string container_id);
};

}

#endif
