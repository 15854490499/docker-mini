#ifndef __UTILS_H__
#define __UTILS_H__

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <regex.h>
#include <dirent.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TIME_STR_SIZE 512
//#define PATH_MAX 1024
#define MAX_MEMORY_SIZE ((size_t)1 << 47)
#define EVENT_ARGS_MAX 255
#define SIZE_KB 1024LL
#define SIZE_MB (1024LL * SIZE_KB)
#define SIZE_GB (1024LL * SIZE_MB)
#define SIZE_TB (1024LL * SIZE_GB)
#define SIZE_PB (1024LL * SIZE_TB)
struct Buffer {
	char *contents;
	size_t bytes_used;
	size_t total_size;
};

typedef struct Buffer Buffer;

typedef bool (*subdir_callback_t)(const char *, struct dirent *, void *);

bool dir_exists(const char* path);
int scan_subdirs(const char *directory, subdir_callback_t cb, void *context);
int mkdir_p(const char* dir, mode_t mode);
char* strdup_s(const char* src);
int array_append(char ***array, const char *element);
void free_array(char** array);
void free_array_by_len(char **array, size_t len);
void* calloc_s(size_t unit_size, size_t count);
void *common_calloc_s(size_t size);
size_t array_len(const char** array);
char **str_array_dup(const char **src, size_t len);
bool has_prefix(const char* str, const char* prefix);
bool has_suffix(const char* str, const char* suffix);
//int base64_encode(unsigned char *bytes, size_t len, char **out);

char *path_join(const char *dir, const char *file);
int path_remove(const char *path);
char *path_dir(const char *path);
char *path_base(const char *path);
char *clean_path(const char *path, char *realpath, size_t realpath_len);
//inline bool abspath(const char *str);
//int normalized_host_os_arch(char **host_os, char **host_arch, char **host_variant);
size_t strlncat(char* dststr, size_t size, const char* srcstr, size_t nsize);

Buffer *buffer_alloc(size_t initial_size);
void buffer_free(Buffer* buf);
int buffer_append(Buffer *buf, const char *append, size_t len);

int dup_array_of_strings(const char **src, size_t src_len, char ***dst, size_t *dst_len);
int mem_realloc(void** newptr, size_t newsize, void* oldptr, size_t oldsize);
int reg_match(const char *patten, const char *str);
bool strings_contains_any(const char *str, const char *substr);
int strings_count(const char *str, unsigned char c);
char **string_split(const char *src_str, char _sep, int *nlen);
char *string_join(const char *sep, const char **parts, size_t len);
char *string_append(const char *post, const char *pre);

int parse_byte_size_string(const char *s, int64_t *converted);
int parse_size_int_and_float(const char *numstr, int64_t mlt, int64_t *converted);
int safe_strtod(const char *numstr, double *converted);
int safe_llong(const char *numstr, long long *converted);
int safe_int(const char *numstr, int *converted);
int safe_int_hex(const char *numstr, int *converted);
int safe_itoa(char *converted, int numstr);
int generate_random_str(char *id, size_t len);

int recursive_rmdir(const char *dirpath, int recursive_depth);
int recursive_remove_path(const char *path);

bool file_exists(const char* f);
char *read_text_file(const char *path);
int write_file(const char* fname, const char* content, size_t content_len, mode_t mode);
ssize_t write_nointr(int fd, const void *buf, size_t count);
ssize_t read_nointr(int fd, void *buf, size_t count);
int atomic_write_file(const char *fname, const char *content, size_t content_len, mode_t mode, bool sync);

#define ExitSignalOffset 128
int wait_for_pid(pid_t pid);
int wait_for_pid_status(pid_t pid);

int gzip_z(const char *srcfile, const char *dstfile, const mode_t mode);

char *oci_default_tag(const char *name);
char *oci_add_host(const char *domain, const char *name);
char *oci_normalize_image_name(const char *name);

int open_devnull();
int set_stdfds(int fd);
int null_stdfds();

#define MAX_IMAGE_NAME_LEN 72
#define __DIGESTPattern "@[a-z0-9]+:[a-z0-9]{32,}"
#define __TagPattern "^:([A-Za-z_0-9][A-Za-z_0-9.-]{0,127})$"
#define __NamePattern                                                                 \
    "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"                             \
    "((\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(:[0-9]+)?/)?[a-z0-9]" \
    "+((([._]|__|[-]*)[a-z0-9]+)+)?((/[a-z0-9]+((([._]|__|[-]*)[a-z0-9]+)+)?)+)?$"
bool valid_image_name(const char *name);
#ifdef __cplusplus
}
#endif

#endif
