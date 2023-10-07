#ifndef __FS_H__
#define __FS_H__

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char *get_fs_name(const char *path);
bool support_d_type(const char *path);
int ensure_mounted_as(const char *dst, unsigned long mntflags, const char *mntdata);
bool detect_mounted(const char *path);
int pre_mount(const char *src, const char *dst, const char *mtype, unsigned long mntflags, const char *mntdata);
int force_mount(const char *src, const char *dst, const char *mtype, unsigned long mntflags, const char *mntdata);
int util_mount(const char *src, const char *dst, const char *mtype, unsigned long mntflags, const char *mntdata);
int list_all_subdir(const char *directory, char ***out, size_t *nlen);
//bool support_overlay(void);

#ifdef __cplusplus
}
#endif


#endif
