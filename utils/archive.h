#ifndef __ARCHIVE_H__
#define __ARCHIVE_H__

#include <stdbool.h>
#include <stdint.h>

#define ARCHIVE_BLOCK_SIZE (32 * 1024);

struct io_read_wrapper;

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	NONE_WHITEOUT_FORMATE = 0,
	OVERLAY_WHITEOUT_FORMATE = 1,
	REMOVE_WHITEOUT_FORMATE = 2,
} whiteout_format_type;

struct archive_options {
	whiteout_format_type whiteout_format;

	const char *src_base;
	const char *dst_base;
};

int archive_unpack(const struct io_read_wrapper *content, const char *dstdir, const struct archive_options *options, char **errmsg);
int archive_unpack_handler(const struct io_read_wrapper *content, const struct archive_options *options);
int archive_copy_oci_tar_split_and_ret_size(int src_fd, const char *dist_file, int64_t *ret_size);
#ifdef __cplusplus
}
#endif

#endif
