#ifndef __ASYNCLOG_H__
#define __ASYNCLOG_H__

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define kSmallBuffer 4096
#define kLargeBuffer 4096 * 1024
#define datas_file "/dev/shm/data.docker-mini"
#define sharedomain_file "/dev/shm/sd.docker-mini"

typedef struct Buffer_item {
	char data[kLargeBuffer];
	int size;
} buffer_item;

struct shared_domain {
	int pput;
	int pget;
	pthread_mutex_t m_mutex;
	pthread_cond_t m_cond;
	pthread_mutex_t t_mutex;
};

struct LogBuffer {
	buffer_item *datas;
	int buffer_size;
	struct shared_domain *pshared_domain;
};

typedef struct Asynclog_ {
	int datas_file_id;
	int sharedomain_file_id;
	struct LogBuffer buffer;
#ifdef REBASETOFILE
	char *filename;
#endif
	void (*append)(char *log_str, int log_str_len);
	void (*start)();
	void (*stop)();
} asynclog;

asynclog *get_g_asynclog();

#ifdef __cplusplus
}
#endif

#endif
