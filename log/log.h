# ifndef __LOG_H__
# define __LOG_H__

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

enum Level {
	UNKNOWN = 0,
	DEBUG = 1,
	INFO = 2,
	WARN = 3,
	ERROR = 4,
	FATAL = 5 
};

typedef struct Logger_ {
	void (*output)(char *file, int line, int level, char *format, ...);
} logger;

logger *get_g_logger();

//#define LOG(level, buf) get_g_logger()->output(__FILE__, __LINE__, level, buf)
#define LOG_DEBUG(format, ...) get_g_logger()->output(__FILE__, __LINE__, DEBUG, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) get_g_logger()->output(__FILE__, __LINE__, INFO, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) get_g_logger()->output(__FILE__, __LINE__, WARN, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) get_g_logger()->output(__FILE__, __LINE__, ERROR, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) get_g_logger()->output(__FILE__, __LINE__, FATAL, format, ##__VA_ARGS__)
#define LOG_UNKNOWN(format, ...) get_g_logger()->output(__FILE__, __LINE__, UNKNOWN, format, ##__VA_ARGS__)


#ifdef __cplusplus
}
#endif

#endif
