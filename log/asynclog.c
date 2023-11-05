#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "asynclog.h"
#include "utils.h"

static pthread_once_t once_control_ = PTHREAD_ONCE_INIT;
static asynclog *g_asynclog;
static bool running_ = false;
static pthread_t tid; 
static pthread_mutex_t mutex;
static pthread_mutexattr_t mutexattr;
static pthread_condattr_t condattr;

void start();
void append(char *log_str, int log_str_len);
void stop();

void once_init() {
	g_asynclog = common_calloc_s(sizeof(asynclog));
	g_asynclog->start = start;
	g_asynclog->append = append;
	g_asynclog->stop = stop;
	g_asynclog->filename = NULL;
    time_t t = time(NULL);
    struct tm *sys_tm = localtime(&t);
    struct tm my_tm = *sys_tm;
    char *file_name = "dockerLog";
	char log_full_name[256] = { 0 };
	int ret = snprintf(log_full_name, 255, "%d_%02d_%02d_%s", my_tm.tm_year + 1900, my_tm.tm_mon + 1, my_tm.tm_mday, file_name);
	if(ret < 0) {
		exit(1);
	}
	g_asynclog->filename = strdup_s(log_full_name);
	pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
	pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&mutex, &mutexattr);
	pthread_mutex_init(&g_asynclog->m_mutex, &mutexattr);
	pthread_cond_init(&g_asynclog->m_cond, &condattr);
	open(shm_file, O_CREAT | O_RDWR, 0666);
	key_t shm_key = ftok(shm_file, 1);
	g_asynclog->buffer.buffer_size = 6;
	g_asynclog->shm_id = shmget(shm_key, sizeof(buffer_item) * g_asynclog->buffer.buffer_size, IPC_CREAT);
	if(g_asynclog->shm_id < 0) {
		printf("obtain shared memory failed : %s\n", strerror(errno));
		goto err_out;
	}
	g_asynclog->buffer.datas = (buffer_item*)shmat(g_asynclog->shm_id, NULL, 0);//common_calloc_s(sizeof(buffer_item) * 16);
	if(g_asynclog->buffer.datas == -1) {
		printf("attach shared memory to %d failed : %s\n", getpid(), strerror(errno));
		goto err_out;
	}
	memset(g_asynclog->buffer.datas, 0, sizeof(buffer_item) * g_asynclog->buffer.buffer_size);
	g_asynclog->buffer.pput = 0;
	g_asynclog->buffer.pget = 0;
	goto out;

err_out:
	if(g_asynclog->shm_id >= 0) {
		shmctl(g_asynclog->shm_id, IPC_RMID, NULL);
	}
out:
	return;
}
asynclog *get_g_asynclog() {
	pthread_once(&once_control_, once_init);
	pthread_mutex_lock(&mutex);
	if(!running_) {
		running_ = true;
		g_asynclog->start();
	}
	pthread_mutex_unlock(&mutex);
	return g_asynclog;
}

void append(char *log_str, int log_str_len) {
	buffer_item *curb = NULL;

	pthread_mutex_lock(&g_asynclog->m_mutex);
	curb = &(g_asynclog->buffer.datas[g_asynclog->buffer.pput]);
	if(curb->size + log_str_len >= kLargeBuffer) {
		g_asynclog->buffer.pput = (g_asynclog->buffer.pput + 1) % g_asynclog->buffer.buffer_size;
 		if(g_asynclog->buffer.pput == g_asynclog->buffer.pget) {
			goto fail;
		}
		curb = &(g_asynclog->buffer.datas[g_asynclog->buffer.pput]);
	}
	/*if(curb->data == NULL) {
		curb->data = (char*)common_calloc_s(kLargeBuffer);
		curb->size = 0;
	}*/
	memcpy(curb->data + curb->size, log_str, log_str_len);
	curb->size += log_str_len;
	pthread_cond_signal(&g_asynclog->m_cond);
	goto out;
fail:
	printf("failed to put %s into buffer\n", log_str);
out:
	pthread_mutex_unlock(&g_asynclog->m_mutex);
	//shmdt(g_asynclog->buffer.datas);
}

static struct timespec *get_abstime() {
	struct timespec *abstime;
	abstime = (struct timespec*)common_calloc_s(sizeof(struct timespec));
	clock_gettime(CLOCK_REALTIME, abstime);
	abstime->tv_sec += 2;
	return abstime;
}

static void log_flush(char *data, int data_size) {
	int n = 0;
	if(data_size == 0) {
		return;
	}
	FILE *fp = fopen(g_asynclog->filename, "a+");
	while(data_size) {
		n = fwrite_unlocked(data + n, 1, data_size, fp);
		if(n == 0) {
			int err = ferror(fp);
			if(err) {
				fprintf(stderr, "fwrite failed\n");
				break;
			}
		}
		data_size -= n;
		data += n;
	}
	fclose(fp);
}

static void *worker(void *arg) {
	struct timespec *abstime = NULL;
	char *data = NULL;
	int data_size = 0;
	int i = 0;
	buffer_item *curb = NULL;

	assert(running_ == true);
	while(running_) {
		pthread_mutex_lock(&g_asynclog->m_mutex);
		if(g_asynclog->buffer.pput == g_asynclog->buffer.pget) {
			abstime = get_abstime();
			pthread_cond_timedwait(&g_asynclog->m_cond, &g_asynclog->m_mutex, abstime);
			free(abstime);
			curb = &(g_asynclog->buffer.datas[g_asynclog->buffer.pget]);
		} else {
			curb = &(g_asynclog->buffer.datas[g_asynclog->buffer.pget]);
			g_asynclog->buffer.pget = (g_asynclog->buffer.pget + 1) % g_asynclog->buffer.buffer_size;
		}
		if(curb->data != NULL && curb->size > 0) {
			data = calloc_s(1, curb->size);
			memcpy(data, curb->data, curb->size);
			data_size = curb->size;
			curb->size = 0;
			memset(curb->data, 0, kLargeBuffer);
			//free(curb->data);
			//curb->data = NULL;
		}
		pthread_mutex_unlock(&g_asynclog->m_mutex);
		if(data != NULL && data_size > 0) {
			log_flush(data, data_size);
			free(data);
			data_size = 0;
		}
	}
	for(i = 0; i < g_asynclog->buffer.buffer_size; i++) {
		data = g_asynclog->buffer.datas[i].data;
		data_size = g_asynclog->buffer.datas[i].size;
		if(data != NULL && data_size > 0) {
			log_flush(data, data_size);
			//free(data);
			data_size = 0;
			memset(curb->data, 0, kLargeBuffer);
		}
	}
	shmdt(g_asynclog->buffer.datas);
	shmctl(g_asynclog->shm_id, IPC_RMID, NULL);
}

void start() {
	pthread_create(&tid, NULL, &worker, NULL);
}

void stop() {
	running_ = false;
	pthread_join(tid, NULL);
}
