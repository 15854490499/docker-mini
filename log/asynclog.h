#ifndef __ASYNCLOG_H__
#define __ASYNCLOG_H__

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define kSmallBuffer 4096
#define kLargeBuffer 4096 * 1024

typedef struct Buffer_item {
	char *data;
	int size;
} buffer_item;

struct LogBuffer {
	buffer_item *datas;
	int buffer_size;
	int pput;
	int pget;
};

typedef struct Asynclog_ {
	pthread_mutex_t m_mutex;
	pthread_cond_t m_cond;
	struct LogBuffer buffer;
	char *filename;
	void (*append)(char *log_str, int log_str_len);
	void (*start)();
	void (*stop)();
} asynclog;

asynclog *get_g_asynclog();

#ifdef __cplusplus
}
#endif

#endif
