#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>

#include "log.h"
#include "utils.h"
#include "asynclog.h"

static logger g_logger;

void output(char *file, int line, int level, char *format, ...);

__attribute__((constructor)) static int ctor() {
	g_logger.output = output;
	return 0;
}

__attribute__((destructor)) static int dtor() {
	get_g_asynclog()->stop();
}

logger *get_g_logger() {
	return &g_logger;
}

static void log_write(char *buf, int len) {
	asynclog *g_asynclog = get_g_asynclog();
	g_asynclog->append(buf, len);
}

static char *format_time(int level) {
	struct timeval tv; 
    time_t time;
    char *str_t = NULL;
	struct tm* p_time = NULL;

	str_t = calloc_s(1, 50);
	if(str_t == NULL) {
		goto out;
	}

    gettimeofday(&tv, NULL);
    time = tv.tv_sec;

	p_time = localtime(&time);
	if(p_time == NULL) {
		goto cleanup;
	}

    strftime(str_t, 26, "%Y-%m-%d %H:%M:%S", p_time);
    switch(level) {
    case 0 : 
        strcat(str_t, "[UNKNOWN]");
        break;
    case 1 : 
        strcat(str_t, "[DEBUG]");
        break;
    case 2 : 
        strcat(str_t, "[INFO]");
        break;
    case 3 : 
        strcat(str_t, "[WARN]");
        break;
    case 4 : 
        strcat(str_t, "[ERROR]");
        break;
    case 5 : 
        strcat(str_t, "[FATAL]");
        break;
    }

	goto out;
cleanup:
	free(str_t);
out:
	return str_t;
}

void output(char *file, int line, int level, char *format, ...) {
    int ret = 0;
	int log_str_len = 0;
	char *str_t = NULL;
	char *log_str = NULL;
	char *tmp_buf = NULL;
	va_list valist;
	
	str_t = format_time(level);
	if(str_t == NULL) {
		goto out;
	}
	
	log_str = calloc_s(1, kLargeBuffer);
	strcat(log_str, str_t);
	if(log_str == NULL) {
		goto out;
	}
	log_str_len += strlen(log_str);

	va_start(valist, format);
	tmp_buf = calloc_s(1, kLargeBuffer);
	ret = vsnprintf(tmp_buf, kLargeBuffer, format, valist);
	if(ret <= 0) {
		goto out;
	}
	log_str_len += ret;

	strcat(log_str, tmp_buf);
	memset(tmp_buf, 0, kLargeBuffer);
	ret = sprintf(tmp_buf, " -- %s:%d\n", file, line);
	if(ret < 0) {
		goto out;
	}
	log_str_len += ret;

	strcat(log_str, tmp_buf);
	log_write(log_str, log_str_len);
out:
	if(str_t != NULL) {
		free(str_t);
	}	
	if(log_str != NULL) {
		free(log_str);
	}
	if(tmp_buf != NULL) {
		free(tmp_buf);
	}
	return;
}
