#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "archive.h"
#include "utils.h"
#include "io_wrapper.h"
#include "storage_entry.h"
#include "log.h"

#define ARCHIVE_READ_BUFFER_SIZE (10 * 1024)
#define ARCHIVE_WRITE_BUFFER_SIZE (10 * 1024)
#define TAR_DEFAULT_MODE 0600
#define TAR_DEFAULT_FLAG (O_WRONLY | O_CREAT | O_TRUNC)

#define WHITEOUT_PREFIX ".wh."
#define WHITEOUT_META_PREFIX ".wh..wh."
#define WHITEOUT_OPAQUEDIR ".wh..wh..opq"

struct archive_context {
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    pid_t pid; 
};

struct archive_content_data {
    const struct io_read_wrapper *content;
    char buff[ARCHIVE_READ_BUFFER_SIZE];
};

ssize_t read_content(struct archive *a, void *client_data, const void **buff)
{
    struct archive_content_data *mydata = client_data;

    memset(mydata->buff, 0, sizeof(mydata->buff));

    *buff = mydata->buff;
    return mydata->content->read(mydata->content->context, mydata->buff, sizeof(mydata->buff));
}

typedef bool (*whiteout_convert_call_back_t)(struct archive_entry *entry, const char *dst_path);

struct whiteout_convert_map {
    whiteout_format_type type;
    whiteout_convert_call_back_t wh_cb;
};
static bool overlay_whiteout_convert_read(struct archive_entry *entry, const char *dst_path);
static bool remove_whiteout_convert(struct archive_entry *entry, const char *dst_path);

struct whiteout_convert_map g_wh_cb_map[] = { { OVERLAY_WHITEOUT_FORMATE, overlay_whiteout_convert_read },
    { REMOVE_WHITEOUT_FORMATE, remove_whiteout_convert }
};

static whiteout_convert_call_back_t get_whiteout_convert_cb(whiteout_format_type whiteout_type)
{
    size_t i = 0;

    for (i = 0; i < sizeof(g_wh_cb_map) / sizeof(g_wh_cb_map[0]); i++) {
        if (whiteout_type == g_wh_cb_map[i].type) {
            return g_wh_cb_map[i].wh_cb;
        }
    }

    return NULL;
}

static bool overlay_whiteout_convert_read(struct archive_entry *entry, const char *dst_path)
{
    bool do_write = true;
    char *base = NULL;
    char *dir = NULL;
    char *originalpath = NULL;

    base = path_base(dst_path);
    if (base == NULL) {
    	LOG_ERROR("Failed to get base of %s\n", dst_path);
        goto out; 
    }    

    dir = path_dir(dst_path);
    if (dir == NULL) {
    	LOG_ERROR("Failed to get dir of %s\n", dst_path);
        goto out; 
    }    

    if (strcmp(base, WHITEOUT_OPAQUEDIR) == 0) { 
        if (setxattr(dir, "trusted.overlay.opaque", "y", 1, 0) != 0) { 
        	LOG_ERROR("Failed to set attr for dir %s\n", dir);
        }
        do_write = false;
        goto out; 
    }    

    if (strncmp(base, WHITEOUT_PREFIX, strlen(WHITEOUT_PREFIX)) == 0) { 
        char *origin_base = &base[strlen(WHITEOUT_PREFIX)];
        originalpath = path_join(dir, origin_base);
        if (originalpath == NULL) {
        	LOG_ERROR("Failed to get original path of %s\n", dst_path);
            goto out; 
        }

        uid_t uid = archive_entry_uid(entry);
        gid_t gid = archive_entry_gid(entry);

    	LOG_ERROR("mknod %s err\n", originalpath);

        if (mknod(originalpath, S_IFCHR, 0) != 0) { 
        	LOG_ERROR("Failed to mknod for dir %s\n", originalpath);
        }

        if (chown(originalpath, uid, gid) != 0) {
        	LOG_ERROR("Failed to chown for dir %s\n", originalpath);
        }
        do_write = false;
        goto out;
    }

out:
    free(base);
    free(dir);
    free(originalpath);
    return do_write;
}

static int remove_files_in_opq_dir(const char *dirpath, int recursive_depth)
{
    struct dirent *pdirent = NULL;
    DIR *directory = NULL;
    int ret = 0; 
    char fname[PATH_MAX] = { 0 }; 

    if ((recursive_depth + 1) > 20) {
    	LOG_ERROR("Reach max path depth: %s", dirpath);
        return -1;
    }    

    directory = opendir(dirpath);
    if (directory == NULL) {
    	LOG_ERROR("Failed to open %s", dirpath);
        return -1;
    }    
    pdirent = readdir(directory);
    for (; pdirent != NULL; pdirent = readdir(directory)) {
        struct stat fstat;
        int pathname_len;

        if (!strcmp(pdirent->d_name, ".") || !strcmp(pdirent->d_name, "..")) {
            continue;
        }

        (void)memset(fname, 0, sizeof(fname));

        pathname_len = snprintf(fname, PATH_MAX, "%s/%s", dirpath, pdirent->d_name);
        if (pathname_len < 0 || pathname_len >= PATH_MAX) {
        	LOG_ERROR("Pathname too long\n");
            ret = -1;
            continue;
        }

        // not exist in unpacked paths map, just remove the path
        /*if (map_search(unpacked_path_map, (void *)fname) == NULL) {
            if (util_recursive_remove_path(fname) != 0) { 
                ERROR("Failed to remove path %s", fname);
                ret = -1;
            }
            continue;
        }*/

        if (lstat(fname, &fstat) != 0) {
        	LOG_ERROR("Failed to stat %s\n", fname);
            ret = -1;
            continue;
        }

        if (S_ISDIR(fstat.st_mode)) {
            if (remove_files_in_opq_dir(fname, recursive_depth + 1) != 0) {
                ret = -1;
                continue;
            }
        }
    }

    if (closedir(directory) != 0) {
    	LOG_ERROR("Failed to close directory %s\n", dirpath);
        ret = -1;
    }

    return ret;
}


static bool remove_whiteout_convert(struct archive_entry *entry, const char *dst_path)
{
    bool do_write = true;
    char *base = NULL;
    char *dir = NULL;
    char *originalpath = NULL;

    base = path_base(dst_path);
    if (base == NULL) {
    	LOG_ERROR("Failed to get base of %s\n", dst_path);
        goto out;
    }

    dir = path_dir(dst_path);
    if (dir == NULL) {
    	LOG_ERROR("Failed to get dir of %s\n", dst_path);
        goto out;
    }

    if (strcmp(base, WHITEOUT_OPAQUEDIR) == 0) {
        if (remove_files_in_opq_dir(dir, 0) != 0) {
        	LOG_ERROR("Failed to remove files in opq dir %s\n", dir);
            goto out;
        }
        do_write = false;
        goto out;
    }

    if (strncmp(base, WHITEOUT_PREFIX, strlen(WHITEOUT_PREFIX)) == 0) {
        char *origin_base = &base[strlen(WHITEOUT_PREFIX)];
        originalpath = path_join(dir, origin_base);
        if (originalpath == NULL) {
        	LOG_ERROR("Failed to get original path of %s\n", dst_path);
            goto out;
        }

        if (recursive_remove_path(originalpath) != 0) {
        	LOG_ERROR("Failed to delete original path %s\n", originalpath);
            goto out;
        }

        do_write = false;
        goto out;
    }

out:
    free(base);
    free(dir);
    free(originalpath);
    return do_write;
}


static char *to_relative_path(const char *path)
{
    char *dst_path = NULL;

    if (path != NULL && path[0] == '/') {
        if (strcmp(path, "/") == 0) {
            dst_path = strdup_s(".");
        } else {
            dst_path = strdup_s(path + 1);
        }
    } else {
        dst_path = strdup_s(path);
    }

    return dst_path;
}

static void free_archive_read(struct archive *read_a)
{
    if (read_a == NULL) {
        return;
    }
    archive_read_close(read_a);
    archive_read_free(read_a);
}

#define READ_BLOCK_SIZE 10240

static struct archive *create_archive_read(int fd)
{
    int nret = 0;
    struct archive *ret = NULL;

    ret = archive_read_new();
    if (ret == NULL) {
    	LOG_ERROR("Out of memory\n");
        return NULL;
    }
    nret = archive_read_support_filter_all(ret);
    if (nret != 0) {
    	LOG_ERROR("archive read support compression all failed\n");
        goto err_out;
    }
    nret = archive_read_support_format_all(ret);
    if (nret != 0) {
    	LOG_ERROR("archive read support format all failed\n");
        goto err_out;
    }
    nret = archive_read_open_fd(ret, fd, READ_BLOCK_SIZE);
    if (nret != 0) {
    	LOG_ERROR("archive read open file failed: %s\n", archive_error_string(ret));
        goto err_out;
    }

    return ret;
err_out:
    free_archive_read(ret);
    return NULL;
}

static int rebase_pathname(struct archive_entry *entry, const char *src_base, const char *dst_base)
{
    int nret = 0;
    const char *pathname = archive_entry_pathname(entry);
    char path[PATH_MAX] = { 0 };

    if (src_base == NULL || dst_base == NULL || !has_prefix(pathname, src_base)) {
        return 0;
    }

    nret = snprintf(path, sizeof(path), "%s%s", dst_base, pathname + strlen(src_base));
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
    	LOG_ERROR("snprintf %s%s failed\n", dst_base, pathname + strlen(src_base));
        fprintf(stderr, "snprintf %s%s failed\n", dst_base, pathname + strlen(src_base));
        return -1;
    }

    archive_entry_set_pathname(entry, path);

    return 0;
}

static char *update_entry_for_pathname(struct archive_entry *entry, const char *src_base, const char *dst_base)
{
    char *dst_path = NULL;
    const char *pathname = NULL;

    if (rebase_pathname(entry, src_base, dst_base) != 0) {
        return NULL;
    }

    pathname = archive_entry_pathname(entry);
    if (pathname == NULL) {
    	LOG_ERROR("Failed to get archive entry path name\n");
        fprintf(stderr, "Failed to get archive entry path name\n");
        return NULL;
    }

    // if path in archive is absolute, we need to translate it to relative because
    // libarchive can not support absolute path when unpack
    dst_path = to_relative_path(pathname);
    if (dst_path == NULL) {
    	LOG_ERROR("translate %s to relative path failed\n", pathname);
        fprintf(stderr, "translate %s to relative path failed\n", pathname);
        goto out;
    }

    archive_entry_set_pathname(entry, dst_path);
out:

    return dst_path;
}

static int rebase_hardlink(struct archive_entry *entry, const char *src_base, const char *dst_base)
{
    int nret = 0;
    const char *linkname = NULL;
    char path[PATH_MAX] = { 0 };

    linkname = archive_entry_hardlink(entry);
    if (linkname == NULL) {
        return 0;
    }

    if (src_base == NULL || dst_base == NULL || !has_prefix(linkname, src_base)) {
        return 0;
    }

    nret = snprintf(path, sizeof(path), "%s%s", dst_base, linkname + strlen(src_base));
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
    	LOG_ERROR("snprintf %s%s failed\n", dst_base, linkname + strlen(src_base));
        fprintf(stderr, "snprintf %s%s failed\n", dst_base, linkname + strlen(src_base));
        return -1;
    }

    archive_entry_set_hardlink(entry, path);

    return 0;
}

static void try_to_replace_exited_dst(const char *dst_path, struct archive_entry *entry)
{
    struct stat s;
    int nret;

    nret = lstat(dst_path, &s);
    if (nret < 0) {
        return;
    }

    if (S_ISDIR(s.st_mode) && archive_entry_filetype(entry) == AE_IFDIR) {
        return;
    }

    if (recursive_remove_path(dst_path) != 0) {
    	LOG_ERROR("Failed to remove path %s while unpack\n", dst_path);
    }

    return;
}

static int copy_data(struct archive *ar, struct archive *aw) 
{
    int r;
    const void *buff = NULL;
    size_t size;
    int64_t offset;

    for (;;) {
        r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF) {
            return ARCHIVE_OK;
        }
        if (r < ARCHIVE_OK) {
            return r;
        }
        r = archive_write_data_block(aw, buff, size, offset);
        if (r < ARCHIVE_OK) {
        	LOG_ERROR("tar extraction error: %s, %s\n", archive_error_string(aw), strerror(archive_errno(aw)));
            return r;
        }
    }    
}

int archive_unpack_handler(const struct io_read_wrapper *content, const struct archive_options *options)
{
    int ret = 0; 
    struct archive *a = NULL;
    struct archive *ext = NULL;
    struct archive_content_data *mydata = NULL;
    struct archive_entry *entry = NULL;
    char *dst_path = NULL;
    int flags;
    whiteout_convert_call_back_t wh_handle_cb = NULL;
    //map_t *unpacked_path_map = NULL; // used for hanling opaque dir, marke paths had been unpacked

    //unpacked_path_map = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    /*if (unpacked_path_map == NULL) {
        ERROR("Out of memory");
        fprintf(stderr, "Out of memory");
        ret = -1;
        goto out; 
    }*/    

    mydata = calloc_s(sizeof(struct archive_content_data), 1);
    if (mydata == NULL) {
    	LOG_ERROR("Memory out\n");
        fprintf(stderr, "Memory out");
        ret = -1;
        goto out; 
    }    
    mydata->content = content;

    flags = ARCHIVE_EXTRACT_TIME;
    flags |= ARCHIVE_EXTRACT_OWNER;
    flags |= ARCHIVE_EXTRACT_PERM;
    flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;
    flags |= ARCHIVE_EXTRACT_SECURE_SYMLINKS;
    flags |= ARCHIVE_EXTRACT_SECURE_NODOTDOT;
    flags |= ARCHIVE_EXTRACT_XATTR;
    flags |= ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS;

    a = archive_read_new();
    if (a == NULL) {
    	LOG_ERROR("archive read new failed\n");
        fprintf(stderr, "archive read new failed\n");
        ret = -1;
        goto out;
    }
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    ext = archive_write_disk_new();
    if (ext == NULL) {
    	LOG_ERROR("archive write disk new failed\n");
        fprintf(stderr, "archive write disk new failed\n");
        ret = -1;
        goto out;
    }
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    ret = archive_read_open(a, mydata, NULL, read_content, NULL);
    if (ret != 0) {
    	LOG_ERROR("Failed to open archive: %s\n", strerror(errno));
        ret = -1;
        goto out;
    }

    wh_handle_cb = get_whiteout_convert_cb(options->whiteout_format);
    for (;;) {
        free(dst_path);
        dst_path = NULL;
        ret = archive_read_next_header(a, &entry);
        if (ret == ARCHIVE_EOF) {
            break;
        }

        if (ret != ARCHIVE_OK) {
        	LOG_ERROR("Warning reading tar header: %s, %s\n", archive_error_string(a), strerror(archive_errno(a)));
            (void)fprintf(stderr, "Warning reading tar header: %s, %s\n", archive_error_string(a),
                          strerror(archive_errno(a)));
            ret = -1;
            goto out;
        }

        dst_path = update_entry_for_pathname(entry, options->src_base, options->dst_base);
        //printf("dst_path: %s\n", dst_path);
        if (dst_path == NULL) {
        	LOG_ERROR("Failed to update pathname\n");
            fprintf(stderr, "Failed to update pathname\n");
            ret = -1;
            goto out;
        }

        ret = rebase_hardlink(entry, options->src_base, options->dst_base);
        if (ret != 0) {
        	LOG_ERROR("Failed to rebase hardlink\n");
            fprintf(stderr, "Failed to rebase hardlink\n");
            ret = -1;
            goto out;
        }

        if (wh_handle_cb != NULL && !wh_handle_cb(entry, dst_path)) {
            continue;
        }

        try_to_replace_exited_dst(dst_path, entry);

        ret = archive_write_header(ext, entry);
        if (ret != ARCHIVE_OK) {
        	LOG_ERROR("Fail to handle tar header: %s, %s\n", archive_error_string(ext), strerror(archive_errno(ext)));
            (void)fprintf(stderr, "Fail to handle tar header: %s, %s\n", archive_error_string(ext),
                          strerror(archive_errno(ext)));
            ret = -1;
            goto out;
        } else if (archive_entry_size(entry) > 0) {
            ret = copy_data(a, ext);
            if (ret != ARCHIVE_OK) {
            	LOG_ERROR("Failed to do copy tar data: %s, %s\n", archive_error_string(ext), strerror(archive_errno(ext)));
                (void)fprintf(stderr, "Failed to do copy tar data: %s, %s\n", archive_error_string(ext),
                              strerror(archive_errno(ext)));
                ret = -1;
                goto out;
            }
        }
        ret = archive_write_finish_entry(ext);
        if (ret != ARCHIVE_OK) {
        	LOG_ERROR("Failed to freeing archive entry: %s, %s\n", archive_error_string(ext), strerror(archive_errno(ext)));
            (void)fprintf(stderr, "Failed to freeing archive entry: %s, %s\n", archive_error_string(ext),
                          strerror(archive_errno(ext)));
            ret = -1;
            goto out;
        }

        /*bool b = true;
        if (!map_replace(unpacked_path_map, (void *)dst_path, (void *)(&b))) {
            ERROR("Failed to replace unpacked path map element");
            fprintf(stderr, "Failed to replace unpacked path map element");
            ret = -1;
            goto out;
        }*/
    }

    ret = 0;

out:
    //map_free(unpacked_path_map);
    free(dst_path);
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    free(mydata);
    return ret;
}

static void close_archive_pipes_fd(int *pipes, size_t pipe_size) {
	size_t i = 0;

	for(i = 0; i < pipe_size; i++) {
		if(pipes[i] >= 0) {
			close(pipes[i]);
			pipes[i] = -1;
		}
	}
}

int archive_unpack(const struct io_read_wrapper *content, const char *dstdir, const struct archive_options *options,
                   char **errmsg)
{
    int ret = 0; 
    pid_t pid = -1;
    int keepfds[] = { -1, -1, -1 };
    int pipe_stderr[2] = { -1, -1 };
    char errbuf[BUFSIZ + 1] = { 0 }; 

    if (pipe2(pipe_stderr, O_CLOEXEC) != 0) { 
    	LOG_ERROR("Failed to create pipe\n");
        ret = -1;
        goto cleanup;
    }    

    pid = fork();
    if (pid == (pid_t) -1) {
    	LOG_ERROR("Failed to fork: %s\n", strerror(errno));
        goto cleanup;
    }    

    if (pid == (pid_t)0) {
        keepfds[1] = *(int *)(content->context);
        keepfds[2] = pipe_stderr[1];
        /*ret = check_inherited_exclude_fds(true, keepfds, 3);
        if (ret != 0) { 
            ERROR("Failed to close fds.");
            fprintf(stderr, "Failed to close fds.");
            ret = -1;
            goto child_out;
        }*/

        // child process, dup2 pipe_for_read[1] to stderr,
        if (dup2(pipe_stderr[1], 2) < 0) { 
        	LOG_ERROR("Dup fd error: %s\n", strerror(errno));
            ret = -1;
            goto child_out;
        }

        if (chroot(dstdir) != 0) { 
        	LOG_ERROR("Failed to chroot to %s\n", dstdir);
            fprintf(stderr, "Failed to chroot to %s: %s", dstdir, strerror(errno));
            ret = -1;
            goto child_out;
        }

        if (chdir("/") != 0) {
        	LOG_ERROR("Failed to chroot to /\n");
            fprintf(stderr, "Failed to chroot to /: %s", strerror(errno));
            ret = -1;
            goto child_out;
        }

        ret = archive_unpack_handler(content, options);

child_out:
        if (ret != 0) {
            exit(EXIT_FAILURE);
        } else {
            exit(EXIT_SUCCESS);
        }
    }
    close(pipe_stderr[1]);
    pipe_stderr[1] = -1;

    ret = wait_for_pid(pid);
    if (ret != 0) {
    	LOG_ERROR("Wait archive_untar_handler failed with error:%s\n", strerror(errno));
        fcntl(pipe_stderr[0], F_SETFL, O_NONBLOCK);
        if (read_nointr(pipe_stderr[0], errbuf, BUFSIZ) < 0) {
        	LOG_ERROR("read error message from child failed\n");
        }
    }

cleanup:
    close_archive_pipes_fd(pipe_stderr, 2);
    if (errmsg != NULL && strlen(errbuf) != 0) {
        *errmsg = strdup_s(errbuf);
    }
    return ret;
}

static int archive_entry_parse(struct archive_entry *entry, struct archive *ar, int32_t position, Buffer *json_buf,
                               int64_t *size)
{
    storage_entry sentry = { 0 };
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, stderr };
    parser_error jerr = NULL;
    char *data = NULL;
    int ret = -1;
    ssize_t nret = 0;
    // get entry information: name, size
    sentry.type = 1;
    sentry.name = strdup_s(archive_entry_pathname(entry));
    sentry.size = archive_entry_size(entry);
    sentry.position = position;
    // caculate playload
    /*if (caculate_playload(ar, &sentry.payload) != 0) {
        ERROR("Caculate playload failed");
        goto out;
    }*/

    data = storage_entry_generate_json(&sentry, &ctx, &jerr);
    if (data == NULL) {
    	LOG_ERROR("parse entry failed: %s\n", jerr);
        goto out;
    }
    nret = buffer_append(json_buf, data, strlen(data));
    if (nret != 0) {
        goto out;
    }
    nret = buffer_append(json_buf, "\n", 1);
    if (nret != 0) {
        goto out;
    }
    *size = *size + sentry.size;

    ret = 0;
out:
    //free_storage_entry(&sentry);
    free(data);
    //free(jerr);
    return ret;
}

int archive_copy_oci_tar_split_and_ret_size(int src_fd, const char *dist_file, int64_t *ret_size)
{
	if (src_fd < 0 || dist_file == NULL || ret_size == NULL) {
    	LOG_ERROR("Invalid arguments");
        return -1;
    }

    const size_t entry_init_buf_size = 4096;
    int ret = -1;
    int nret = 0;
    struct archive *read_a = NULL;
    struct archive_entry *entry = NULL;
    int32_t position = 0;
    Buffer *json_buf = NULL;

    // we need reset fd point to first position
    if (lseek(src_fd, 0, SEEK_SET) == -1) {
    	LOG_ERROR("can not reposition of archive file");
        return -1;
    }
    json_buf = buffer_alloc(entry_init_buf_size);
    if (json_buf == NULL) {
    	LOG_ERROR("Failed to malloc output_buffer");
        return -1;
    }    

    read_a = create_archive_read(src_fd);
    if (read_a == NULL) {
        goto out;
    }
    for (;;) {
        nret = archive_read_next_header(read_a, &entry);
        if (nret == ARCHIVE_EOF) {
        	LOG_INFO("read entry: %d", position);
            break;
        }
        if (nret != ARCHIVE_OK) {
        	LOG_ERROR("archive read header failed: %s", archive_error_string(read_a));
            goto out;
        }
        nret = archive_entry_parse(entry, read_a, position, json_buf, ret_size);
        if (nret != 0) {
            goto out;
        }
        position++;
    }
    nret = atomic_write_file(dist_file, json_buf->contents, json_buf->bytes_used, 0644, true);
    if (nret != 0) {
    	LOG_ERROR("save tar split failed");
        goto out;
    }
	
	ret = 0;
out:
	buffer_free(json_buf);
	free_archive_read(read_a);
	return ret;
}
