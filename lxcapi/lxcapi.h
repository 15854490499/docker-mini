#ifndef __LXCAPI_H__
#define __LXCAPI_H__

#include "utils.h"
#include "oci_runtime_spec.h"

#define runtime_dir "/var/lib/docker-mini/runtime"
#define run_dir "/var/lib/docker-mini/run"
#define DEFAULT_NET_TYPE "veth"
#define DEFAULT_NET_LINK "docker-mini0"
#define DEFAULT_BUF_LEN 128
#define DEFAULT_CPU_PERIOD 100000
#define COMMON_CONFIG "/usr/local/share/lxc/config/common.conf"
#define PARAM_NUM 30
#define DEFAULT_LOGLEVEL "trace"
#define DEFAULT_TIMEOUT 120
#define LXC_IMAGE_OCI_KEY "lxc.imagetype.oci"
#define LXC_DEFAULT_START_COMMAND "/bin/bash"

#define lxc_list_for_each(__iterator, __list) \
    for ((__iterator) = (__list)->next; \
         (__iterator) != (__list); \
         (__iterator) = (__iterator)->next)

struct lxc_params_list {
	void *data;
	struct lxc_params_list *next;
	struct lxc_params_list *prev;
};

static inline void lxc_params_list_init(struct lxc_params_list *list) {
	list->data = NULL;
	list->next = list->prev = list;
}

static inline void lxc_list_add(struct lxc_params_list *head, struct lxc_params_list *list) {
	list->prev = head;
	list->next = head->next;
	head->next->prev = list;
	head->next = list;
}

static inline void lxc_list_merge(struct lxc_params_list *l1, struct lxc_params_list *l2) {
	struct lxc_params_list *l1_tail, *l2_tail;
	l1_tail = l1->prev;
	l2_tail = l2->prev;

	l1->prev = l2_tail;
	l1_tail->next = l2;
	l2->prev = l1_tail;
	l2_tail->next = l1;
}

struct lxc_start_request {
	char *name;
	char *path;
	char *logpath;
	char *loglevel;
	unsigned int start_timeout;
	bool daemonize;
	bool image_type_oci;
};

struct lxc_attach_request {
	char *name;
	char *path;
	char *logpath;
	char *loglevel;
};

int runtime_start(const char *id, const char *config_path);
int runtime_stop(const char *id);
int runtime_create(const char *id, oci_runtime_spec *container_spec);
int runtime_attach(const char *id, const char *config_path);
#endif
