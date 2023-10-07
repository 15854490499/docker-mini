#ifndef __IO_WRAPPER_H__
#define __IO_WRAPPER_H__

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	FIFO_IN_IO = 0,
	FIFO_OUT_IO,
	FIFO_ERR_IO,
	FUNC_IN_IO,
	FUNC_OUT_IO,
	FUNC_ERR_IO,
};

typedef ssize_t (*io_write_func_t)(void *context, const void *data, size_t len);
typedef int (*io_close_func_t)(void *context, char **err);

struct io_write_wrapper {
	void *context;
	io_write_func_t write_func;
	io_close_func_t close_func;
	int io_type;
};

typedef ssize_t (*io_read_func_t)(void *context, void *buf, size_t len);

struct io_read_wrapper {
	void *context;
	io_read_func_t read;
	io_close_func_t close;
	int io_type;
};

#ifdef __cplusplus
}
#endif

#endif
