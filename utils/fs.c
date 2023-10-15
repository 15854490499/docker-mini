#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/mount.h>

#include "fs.h"
#include "utils.h"
#include "log.h"

#ifndef JFS_SUPER_MAGIC
#define JFS_SUPER_MAGIC 0x3153464a
#endif

#ifndef VXFS_SUPER_MAGIC
#define VXFS_SUPER_MAGIC 0xa501fcf5
#endif

#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif

#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif

#ifndef AUFS_SUPER_MAGIC
#define AUFS_SUPER_MAGIC 0x61756673
#endif

#ifndef GPFS_SUPER_MAGIC
#define GPFS_SUPER_MAGIC 0x47504653
#endif

#ifndef UNSUPPORTED_MAGIC
#define UNSUPPORTED_MAGIC 0x00000000
#endif

#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif

#ifndef ZFS_SUPER_MAGIC
#define ZFS_SUPER_MAGIC 0x2fc12fc1
#endif

#define PROPAGATION_TYPES (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)
#define PROPAGATION_FLAGS (PROPAGATION_TYPES | MS_REC | MS_SILENT)
#define BRO_FLAGS (MS_BIND | MS_RDONLY)

struct fs_element {
	const char *fs_name;
	uint32_t fs_magic;
};

static struct fs_element const g_fs_names[] = {
    { "aufs", AUFS_SUPER_MAGIC },
    { "btrfs", BTRFS_SUPER_MAGIC },
    { "cramfs", CRAMFS_MAGIC },
    { "ecryptfs", ECRYPTFS_SUPER_MAGIC },
    { "extfs", EXT2_SUPER_MAGIC },
    { "f2fs", F2FS_SUPER_MAGIC },
    { "gpfs", GPFS_SUPER_MAGIC },
    { "jffs2", JFFS2_SUPER_MAGIC },
    { "jfs", JFS_SUPER_MAGIC },
    { "nfs", NFS_SUPER_MAGIC },
    { "overlayfs", OVERLAYFS_SUPER_MAGIC },
    { "ramfs", RAMFS_MAGIC },
    { "reiserfs", REISERFS_SUPER_MAGIC },
    { "smb", SMB_SUPER_MAGIC },
    { "squashfs", SQUASHFS_MAGIC },
    { "tmpfs", TMPFS_MAGIC },
    { "unsupported", UNSUPPORTED_MAGIC },
    { "vxfs", VXFS_SUPER_MAGIC },
    { "xfs", XFS_SUPER_MAGIC },
    { "zfs", ZFS_SUPER_MAGIC },	
};

char *get_fs_name(const char *path) {
	int ret = 0;
	size_t i = 0;
	char *ans = (char*)calloc(1, 512);
	char *t = NULL;
	struct statfs fs_state;

	if(path == NULL) {
		return NULL;
	}

	ret = statfs(path, &fs_state);
	if(ret < 0) {
		return NULL;
	}

	for(i = 0; i < sizeof(g_fs_names) / sizeof(g_fs_names[0]); i++) {
		if(g_fs_names[i].fs_magic == fs_state.f_type) {
			/*for(int j = 0; j < strlen(g_fs_names[i].fs_name); j++) {
				ans[j] = g_fs_names[i].fs_name[j];
			}
			t = strdup(ans);
			break;*/
			return strdup_s(g_fs_names[i].fs_name);
		}
	}
	return NULL;
}

static char *get_mtpoint(const char *line)
{
    int i;
    const char *tmp = NULL;
    char *pend = NULL;
    char *sret = NULL;
    size_t len;

    if (line == NULL) {
        goto err_out;
    }

    tmp = line;
    for (i = 0; i < 4; i++) {
        tmp = strchr(tmp, ' ');
        if (tmp == NULL) {
            goto err_out;
        }
        tmp++;
    }
    pend = strchr(tmp, ' ');
    if ((pend == NULL) || pend == tmp) {
        goto err_out;
    }

    /* stuck a \0 after the mountpoint */
    len = (size_t)(pend - tmp);
    sret = (char*)malloc(len + 1);
    if (sret == NULL) {
        goto err_out;
    }
    memcpy(sret, tmp, len);
    sret[len] = '\0';

err_out:
    return sret;
}

bool detect_mounted(const char *path) {
	FILE *fp = NULL;
	char *line = NULL;
	char *mountpoint = NULL;
	size_t length = 0;
	bool bret = false;

	fp = fopen("/proc/self/mountinfo", "r");
	if(fp == NULL) {
		LOG_ERROR("Failed opening /proc/self/mountinfo\n");
		return false;
	}

	while(getline(&line, &length, fp) != -1) {
		mountpoint = get_mtpoint(line);
		if(mountpoint == NULL) {
			LOG_ERROR("Error reading mountinfo: bad line '%s'\n", line);
			continue;
		}
		if(strcmp(mountpoint, path) == 0) {
			free(mountpoint);
			bret = true;
			goto out;
		}
		free(mountpoint);
	}
out:
	fclose(fp);
	free(line);
	return bret;
}

static bool is_remount(const char *src, unsigned long mntflags)
{
    if ((mntflags & MS_REMOUNT) != 0 || strcmp(src, "") == 0 || strcmp(src, "none") == 0) {
        return true;
    }   

    return false;
}

int force_mount(const char *src, const char *dst, const char *mtype, unsigned long mntflags, const char *mntdata) {
	int ret = 0;
	unsigned long oflags = mntflags & (~PROPAGATION_TYPES);
	if(!is_remount(src, mntflags) || (mntdata != NULL && strcmp(mntdata, "") != 0)) {
		ret = mount(src, dst, mtype, oflags, mntdata);
		if(ret < 0) {
			LOG_ERROR("Failed to mount %s to %s:%s\n", src, dst, strerror(errno));
			goto out;
		}
	}

	if((mntflags & PROPAGATION_TYPES) != 0) {
		ret = mount("", dst, "", mntflags & PROPAGATION_FLAGS, "");
		if(ret < 0) {
			LOG_ERROR("Failed to change the propagation type of dst %s:%s\n", dst, strerror(errno));
			goto out;
		}
	}

	if((oflags & BRO_FLAGS) == BRO_FLAGS) {
		ret = mount("", dst, "", oflags | MS_REMOUNT, "");
		if(ret < 0) {
			LOG_ERROR("Failed to remount the bind to apply read only of dst %s:%s\n", dst, strerror(errno));
			goto out;
		}
	}
out:
	return ret;
}

int pre_mount(const char *src, const char *dst, const char *mtype, unsigned long mntflags, const char *mntdata) {
	int ret = 0;

	if(src == NULL || dst == NULL || mtype == NULL) {
		return -1;
	}
	
	if((mntflags & MS_REMOUNT) != MS_REMOUNT) {
		if(detect_mounted(dst)) {
			LOG_ERROR("mount dst %s has been mounted, skip mount\n", dst);
			ret = 0;
			goto out;
		}
	}

	ret = force_mount(src, dst, mtype, mntflags, mntdata);
out:
	return ret;
}

int ensure_mounted_as(const char *dst, unsigned long mntflags, const char *mntdata) {
	int ret = 0;
	bool mounted = false;

	if(dst == NULL) {
		return -1;
	}

	mounted = detect_mounted(dst);

	if(!mounted) {
		unsigned long mntflags = 0L;
		mntflags &= ~MS_RDONLY;
		mntflags |= MS_BIND;
		ret = pre_mount(dst, dst, "none", mntflags, NULL);
		if(ret != 0) {
			goto out;
		}
	}

	ret = force_mount("", dst, "none", mntflags, mntdata);

out:
	return ret;
}

int util_mount(const char *src, const char *dst, const char *mtype, unsigned long mntflags, const char *mntdata) {
	int ret = 0;
	
	if(src == NULL || dst == NULL || mtype == NULL) {
		return -1;
	}

	if((mntflags & MS_REMOUNT) != MS_REMOUNT) {
		if(detect_mounted(dst)) {
			LOG_ERROR("mount dst %s had been mounted\n", dst);
			ret = 0;
			goto out;
		}
	}

	ret = force_mount(src, dst, mtype, mntflags, mntdata);
out:
	return ret;
}

bool support_d_type(const char *path)
{
    bool is_support_d_type = true;
    DIR *dir = NULL;
    struct dirent *entry = NULL;

    if (path == NULL) {
        return false;
    }

    dir = opendir(path);
    if (dir == NULL) {
    	LOG_ERROR("opendir %s failed.\n", path);
        return false;
    }

    entry = readdir(dir);
    for (; entry != NULL; entry = readdir(dir)) {
        if (entry->d_type == DT_UNKNOWN) {
        	LOG_ERROR("d_type found to be DT_UNKNOWN\n");
            is_support_d_type = false;
            break;
        }
    }
    closedir(dir);

    return is_support_d_type;
}

int list_all_subdir(const char *directory, char ***out, size_t *nlen)
{
    DIR *dir = NULL;
    struct dirent *direntp = NULL;
    char **names_array = NULL;
    char tmpdir[PATH_MAX] = { 0 }; 
    int nret;
	int len = 0;

    if (directory == NULL || out == NULL) {
        return -1;
    }    

    dir = opendir(directory);
    if (dir == NULL) {
    	LOG_ERROR("Failed to open directory: %s error:%s\n", directory, strerror(errno));
        return -1;
    }    
    direntp = readdir(dir);
    for (; direntp != NULL; direntp = readdir(dir)) {
        if (strncmp(direntp->d_name, ".", PATH_MAX) == 0 || strncmp(direntp->d_name, "..", PATH_MAX) == 0) { 
            continue;
        }

        nret = snprintf(tmpdir, PATH_MAX, "%s/%s", directory, direntp->d_name);
        if (nret < 0 || nret >= PATH_MAX) {
        	LOG_ERROR("Sprintf: %s failed\n", direntp->d_name);
            goto error_out;
        }
        if (!dir_exists(tmpdir)) {
        	LOG_ERROR("%s is not directory\n", direntp->d_name);
            continue;
        }
        if (array_append(&names_array, direntp->d_name)) {
        	LOG_ERROR("Failed to append subdirectory array\n");
            goto error_out;
        }
		len++;
    }    

    closedir(dir);
    *out = names_array;
	*nlen = len;
    return 0;

error_out:
    closedir(dir);
    free_array(names_array);
    names_array = NULL;
    return -1;
}

/*bool support_overlay(void) {
	bool is_support = false;
	FILE *f = NULL;
	char *line
}*/
