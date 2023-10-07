#include <pthread.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/dqblk_xfs.h>
#include <linux/quota.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/quota.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "project_quota.h"

#include "utils.h"

// define for quotactl commands
#define PDQ_ACCT_BIT 4 // 4 means project quota accounting ops
#define PDQ_ENFD_BIT 5 // 5 means project quota limits enforcement

// make device of the driver home directory
static char *make_backing_fs_device(const char *home_dir)
{
    int ret = 0;
    char full_path[PATH_MAX] = { 0 };
    struct stat current_stat = { 0 };

    ret = snprintf(full_path, PATH_MAX, "%s/%s", home_dir, "backingFsBlockDev");
    if (ret < 0 || ret >= PATH_MAX) {
        printf("Failed to get backing fs device\n");
        goto err_out;
    }

    ret = stat(home_dir, &current_stat);
    if (ret) {
        printf("get %s state failed\n", home_dir);
        goto err_out;
    }

    unlink(full_path);
    ret = mknod(full_path, S_IFBLK | S_IRUSR | S_IWUSR, current_stat.st_dev);
    if (ret != 0) {
        printf("Failed to mknod %s\n", full_path);
        goto err_out;
    }

    return strdup_s(full_path);

err_out:
    return NULL;
}

static int set_project_quota_id(const uint32_t projectid, const char *target)
{
    int ret = 0;
    struct fsxattr fsxattr_for_prjid = { 0 };
    DIR *dir = NULL;
    int fd = -1;

    dir = opendir(target);
    if (dir == NULL) {
        ret = -1;
        printf("opendir with path %s failed\n", target);
        goto out;
    }

    fd = dirfd(dir);
    if (fd < 0) {
        ret = -1;
        printf("open %s failed.\n", target);
        goto out;
    }

    ret = ioctl(fd, FS_IOC_FSGETXATTR, &fsxattr_for_prjid);
    if (ret != 0) {
        printf("failed to get projid for %s\n", target);
        goto out;
    }

    fsxattr_for_prjid.fsx_projid = projectid;
    fsxattr_for_prjid.fsx_xflags |= FS_XFLAG_PROJINHERIT;
    ret = ioctl(fd, FS_IOC_FSSETXATTR, &fsxattr_for_prjid);
    if (ret != 0) {
        printf("failed to set projid for %s\n", target);
        goto out;
    }

out:
    if (dir != NULL) {
        closedir(dir);
    }
    return ret;
}

static int ext4_set_project_quota(const char *backing_fs_blockdev, uint32_t project_id, uint64_t size)
{
    int ret;
    struct dqblk d = { 0 };
    d.dqb_bhardlimit = size / SIZE_KB;
    d.dqb_bsoftlimit = d.dqb_bhardlimit;
    d.dqb_valid = QIF_LIMITS;

    ret = quotactl(QCMD(Q_SETQUOTA, FS_PROJ_QUOTA), backing_fs_blockdev, project_id, (caddr_t)&d);
    if (ret != 0) {
        printf("Failed to set quota limit for projid %d on %s\n", project_id, backing_fs_blockdev);
    }
    return ret;
}

static int ext4_set_quota(const char *target, struct pquota_control *ctrl, uint64_t size)
{
    int ret = 0;
    uint32_t project_id = 0;

    if (target == NULL || ctrl == NULL) {
        return -1;
    }

    project_id = ctrl->next_project_id;
    if (set_project_quota_id(project_id, target) != 0) {
        printf("Failed to set project id %d to %s.\n", project_id, target);
        ret = -1;
		goto out;
    }
    ctrl->next_project_id++;

    printf("Set directory %s project ID:%u quota size: %lu\n", target, project_id, size);

    if (ext4_set_project_quota(ctrl->backing_fs_device, project_id, size) != 0) {
        printf("Failed to set project id %d to %s.\n", project_id, target);
        ret = -1;
    }

out:
    return ret;
}

static int xfs_set_project_quota(const char *backing_fs_blockdev, uint32_t project_id, uint64_t size)
{
    int ret;
    fs_disk_quota_t d = { 0 };
    d.d_version = FS_DQUOT_VERSION;
    d.d_id = project_id;
    d.d_flags = FS_PROJ_QUOTA;
    d.d_fieldmask = FS_DQ_BHARD | FS_DQ_BSOFT;
    d.d_blk_hardlimit = (size / 512);
    d.d_blk_softlimit = d.d_blk_hardlimit;

    ret = quotactl(QCMD(Q_XSETQLIM, FS_PROJ_QUOTA), backing_fs_blockdev, project_id, (caddr_t)&d);
    if (ret != 0) {
        printf("Failed to set quota limit for projid %d on %s\n", project_id, backing_fs_blockdev);
    }
    return ret;
}

static int xfs_set_quota(const char *target, struct pquota_control *ctrl, uint64_t size)
{
    int ret = 0;
    uint32_t project_id = 0;

    if (target == NULL || ctrl == NULL) {
        return -1;
    }

    project_id = ctrl->next_project_id;
    if (set_project_quota_id(project_id, target) != 0) {
        printf("Failed to set project id %d to %s.\n", project_id, target);
        ret = -1;
		goto out;
    }
    ctrl->next_project_id++;

    printf("Set directory %s project ID:%u quota size: %lu\n", target, project_id, size);

    if (xfs_set_project_quota(ctrl->backing_fs_device, project_id, size) != 0) {
        printf("Failed to set project id %d to %s.\n", project_id, target);
        ret = -1;
    }

out:
    return ret;
}

static int get_project_quota_id(const char *path, uint32_t *project_id)
{
    int ret = 0;
    DIR *dir = NULL;
    int fd = -1;
    struct fsxattr fsxattr = { 0 };

    dir = opendir(path);
    if (dir == NULL) {
        ret = -1;
        printf("opendir with path %s failed\n", path);
        goto out;
    }
    fd = dirfd(dir);
    if (fd < 0) {
        ret = -1;
        printf("open %s failed.\n", path);
        goto out;
    }
    ret = ioctl(fd, FS_IOC_FSGETXATTR, &fsxattr);
    if (ret != 0) {
        printf("failed to get projid for %s\n", path);
        goto out;
    }

    *project_id = (uint32_t)fsxattr.fsx_projid;
out:
    if (dir != NULL) {
        closedir(dir);
    }
    return ret;
}

static void get_next_project_id(const char *dirpath, struct pquota_control *ctrl)
{
    int nret = 0;
    struct dirent *pdirent = NULL;
    DIR *directory = NULL;
    char fname[PATH_MAX];

    directory = opendir(dirpath);
    if (directory == NULL) {
        printf("Failed to open %s\n", dirpath);
        return;
    }
    pdirent = readdir(directory);
    for (; pdirent != NULL; pdirent = readdir(directory)) {
        struct stat fstat;
        int pathname_len;
        uint32_t project_id = 0;

        if (!strcmp(pdirent->d_name, ".") || !strcmp(pdirent->d_name, "..")) {
            continue;
        }

        (void)memset(fname, 0, sizeof(fname));

        pathname_len = snprintf(fname, PATH_MAX, "%s/%s", dirpath, pdirent->d_name);
        if (pathname_len < 0 || pathname_len >= PATH_MAX) {
            printf("Pathname too long\n");
            continue;
        }

        nret = lstat(fname, &fstat);
        if (nret != 0) {
            printf("get_next_project_id failed to stat %s\n", fname);
            continue;
        }

        if (!S_ISDIR(fstat.st_mode)) {
            continue;
        }

        if (get_project_quota_id(fname, &project_id) != 0) {
            printf("Failed to get %s project id\n", fname);
            continue;
        }
        if (ctrl->next_project_id <= project_id) {
            ctrl->next_project_id = project_id + 1;
        }
    }

    nret = closedir(directory);
    if (nret) {
        printf("Failed to close directory %s\n", dirpath);
    }
}

void free_pquota_control(struct pquota_control *ctrl)
{
    if (ctrl == NULL) {
        return;
    }

    free(ctrl->backing_fs_type);
    ctrl->backing_fs_type = NULL;

    free(ctrl->backing_fs_device);
    ctrl->backing_fs_device = NULL;

    free(ctrl);
}

static int get_quota_stat(const char *backing_fs_blockdev)
{
    int ret = 0;
    int nret = 0;
    fs_quota_stat_t fs_quota_stat_info = { 0 };

    ret = quotactl(QCMD(Q_XGETQSTAT, FS_PROJ_QUOTA), backing_fs_blockdev, 0, (caddr_t)&fs_quota_stat_info);
    if (ret != 0) {
        printf("Failed to get quota stat on %s\n", backing_fs_blockdev);
        return ret;
    }

    nret = ((fs_quota_stat_info.qs_flags & FS_QUOTA_PDQ_ACCT) >> PDQ_ACCT_BIT) +
           ((fs_quota_stat_info.qs_flags & FS_QUOTA_PDQ_ENFD) >> PDQ_ENFD_BIT);
    if (nret == FS_PROJ_QUOTA) { // return FS_PROJ_QUOTA(2) means project quota is on
        ret = 0;
    } else {
        ret = -1;
    }

    return ret;
}

static bool fs_support_quota(const char *fs)
{
    if (fs == NULL) {
        return false;
    }

    return (strcmp(fs, "xfs") == 0 || strcmp(fs, "extfs") == 0);
}

struct pquota_control *project_quota_control_init(const char *home_dir, const char *fs)
{
    int ret = 0;
    struct pquota_control *ctrl = NULL;
    uint32_t min_project_id = 0;

    if (home_dir == NULL || fs == NULL) {
        printf("Invalid input auguments\n");
        goto err_out;
    }

    if (!fs_support_quota(fs)) {
        printf("quota isn't supported for filesystem %s\n", fs);
        goto err_out;
    }

    ctrl = calloc_s(1, sizeof(struct pquota_control));
    if (ctrl == NULL) {
        printf("out of memory\n");
        goto err_out;
    }

    if (ret) {
        printf("init project quota rwlock failed\n");
        goto err_out;
    }

    ret = get_project_quota_id(home_dir, &min_project_id);
    if (ret) {
        printf("Failed to get mininal project id %s\n", home_dir);
        goto err_out;
    }
    min_project_id++;
    ctrl->next_project_id = min_project_id;
    get_next_project_id(home_dir, ctrl);

    ctrl->backing_fs_device = make_backing_fs_device(home_dir);
    if (ctrl->backing_fs_device == NULL) {
        printf("Failed to make backing fs device %s\n", home_dir);
        goto err_out;
    }

    if (get_quota_stat(ctrl->backing_fs_device) != 0) {
        printf("quota isn't supported on your system %s\n", home_dir);
        goto err_out;
    }

    ctrl->backing_fs_type = strdup_s(fs);

    if (strcmp(ctrl->backing_fs_type, "extfs") == 0) {
        ctrl->set_quota = ext4_set_quota;
    } else {
        ctrl->set_quota = xfs_set_quota;
    }

    return ctrl;

err_out:
    free_pquota_control(ctrl);
    return NULL;
}
