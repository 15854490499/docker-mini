#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>  
#include <ctype.h>
#include <limits.h>
#include <regex.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <termios.h> // IWYU pragma: keep
#include <strings.h>
#include <zlib.h>

#include "log.h"

struct unit_map_def {
	int64_t mltpl;
	char *name;
};


static struct unit_map_def const g_unit_map[] = {
    { .mltpl = 1, .name = "I" },         { .mltpl = 1, .name = "B" },         { .mltpl = 1, .name = "IB" },
    { .mltpl = SIZE_KB, .name = "K" },   { .mltpl = SIZE_KB, .name = "KI" },  { .mltpl = SIZE_KB, .name = "KB" },
    { .mltpl = SIZE_KB, .name = "KIB" }, { .mltpl = SIZE_MB, .name = "M" },   { .mltpl = SIZE_MB, .name = "MI" },
    { .mltpl = SIZE_MB, .name = "MB" },  { .mltpl = SIZE_MB, .name = "MIB" }, { .mltpl = SIZE_GB, .name = "G" },
    { .mltpl = SIZE_GB, .name = "GI" },  { .mltpl = SIZE_GB, .name = "GB" },  { .mltpl = SIZE_GB, .name = "GIB" },
    { .mltpl = SIZE_TB, .name = "T" },   { .mltpl = SIZE_TB, .name = "TI" },  { .mltpl = SIZE_TB, .name = "TB" },
    { .mltpl = SIZE_TB, .name = "TIB" }, { .mltpl = SIZE_PB, .name = "P" },   { .mltpl = SIZE_PB, .name = "PI" },
    { .mltpl = SIZE_PB, .name = "PB" },  { .mltpl = SIZE_PB, .name = "PIB" }
};

static size_t const g_unit_map_len = sizeof(g_unit_map) / sizeof(g_unit_map[0]);

#define ISSLASH(C) ((C) == '/')
#define IS_ABSOLUTE_FILE_NAME(F) (ISSLASH((F)[0]))
#define IS_RELATIVE_FILE_NAME(F) (!IS_ABSOLUTE_FILE_NAME(F))

static bool do_clean_path_continue(const char *endpos, const char *stpos, const char *respath, char **dst)
{
    if (endpos - stpos == 1 && stpos[0] == '.') {
        return true;
    } else if (endpos - stpos == 2 && stpos[0] == '.' && stpos[1] == '.') {
        char *dest = *dst;
        if (dest <= respath + 1) {
            return true;
        }
        for (--dest; dest > respath && !ISSLASH(dest[-1]); --dest) {
            continue;
        }
        *dst = dest;
        return true;
    }
    return false;
}

static int do_clean_path(const char *respath, const char *limit_respath, const char *stpos, char **dst)
{
    char *dest = *dst;
    const char *endpos = NULL;

    for (; *stpos; stpos = endpos) {
        while (ISSLASH(*stpos)) {
            ++stpos;
        }

        for (endpos = stpos; *endpos && !ISSLASH(*endpos); ++endpos) {
        }

        if (endpos - stpos == 0) {
            break;
        } else if (do_clean_path_continue(endpos, stpos, respath, &dest)) {
            continue;
        }

        if (!ISSLASH(dest[-1])) {
            *dest++ = '/';
        }

        if (dest + (endpos - stpos) >= limit_respath) {
        	LOG_ERROR("Path is too long\n");
            if (dest > respath + 1) {
                dest--;
            }
            *dest = '\0';
            return -1;
        }

        (void)memcpy(dest, stpos, (size_t)(endpos - stpos));
        dest += endpos - stpos;
        *dest = '\0';
    }
    *dst = dest;
    return 0;
}

char *clean_path(const char *path, char *realpath, size_t realpath_len)
{
    char *respath = NULL;
    char *dest = NULL;
    const char *stpos = NULL;
    const char *limit_respath = NULL;

    if (path == NULL || path[0] == '\0' || realpath == NULL || (realpath_len < PATH_MAX)) {
        return NULL;
    }   

    respath = realpath;

    (void)memset(respath, 0, realpath_len);
    limit_respath = respath + PATH_MAX;

    if (!IS_ABSOLUTE_FILE_NAME(path)) {
        if (!getcwd(respath, PATH_MAX)) {
        	LOG_ERROR("Failed to getcwd\n");
            respath[0] = '\0';
            goto error;
        }
        dest = strchr(respath, '\0');
        if (dest == NULL) {
        	LOG_ERROR("Failed to get the end of respath\n");
            goto error;
        }
        if (strlen(path) >= (PATH_MAX - 1) - strlen(respath)) {
        	LOG_ERROR("%s path too long\n", path);
            goto error;
        }
        (void)strcat(respath, path);
        stpos = path;
    } else {
        dest = respath;
        *dest++ = '/';
        stpos = path;
    }   

    if (do_clean_path(respath, limit_respath, stpos, &dest)) {
        goto error;
    }

    if (dest > respath + 1 && ISSLASH(dest[-1])) {
        --dest;
    }
    *dest = '\0';

    return respath;

error:
    return NULL;
}


char *path_join(const char *dir, const char *file)
{
    int nret = 0; 
    char path[PATH_MAX] = { 0 }; 
    char cleaned[PATH_MAX] = { 0 }; 

    if (dir == NULL || file == NULL) {
    	LOG_ERROR("NULL dir or file, failed\n");
        return NULL;
    }    

    nret = snprintf(path, PATH_MAX, "%s/%s", dir, file);
    if (nret < 0 || nret >= PATH_MAX) {
    	LOG_ERROR("dir or file too long, failed\n");
        return NULL;
    }    

    /*if (util_clean_path(path, cleaned, sizeof(cleaned)) == NULL) {
    	LOG_ERROR("Failed to clean path: %s", path);
        return NULL;
    } */   

    return strdup_s(path);
}

int path_remove(const char *path) {
	int saved_errno;
	if(path == NULL) {
		return -1;
	}
	if(unlink(path) == 0 || errno == ENOENT) {
		return 0;
	}
	saved_errno = errno;
	if(rmdir(path) == 0 || errno == ENOENT) {
		return 0;
	}
	if(errno == ENOTDIR) {
		errno = saved_errno;
	}
	return -1;
}

char *path_dir(const char *path) {
	char *dir = NULL;
	int len = 0;
	int i = 0;
	
	if(path == NULL) {
		LOG_ERROR("invalid NULL param\n");
		return NULL;
	}
	
	len = (int)strlen(path);
	if(len == 0) {
		return strdup_s(".");
	}

	dir = strdup_s(path);

	for(i = len - 1; i > 0; i--) {
		if(dir[i] == '/') {
			dir[i] = 0;
			break;
		}
	}

	if(i == 0 && dir[0] == '/') {
		free(dir);
		return strdup_s("/");
	}
	return dir;
}

char *path_base(const char *path)
{
    char *dir = NULL;
    int len = 0; 
    int i = 0; 

    if (path == NULL) {
    	LOG_ERROR("invalid NULL param\n");
        return NULL;
    }    

    len = (int)strlen(path);
    if (len == 0) { 
        return strdup_s(".");
    }    

    dir = strdup_s(path);

    // strip last slashes
    for (i = len - 1; i >= 0; i--) {
        if (dir[i] != '/') {
            break;
        }
        dir[i] = '\0';
    }    

    len = (int)strlen(dir);
    if (len == 0) { 
        free(dir);
        return strdup_s("/");
    }    

    for (i = len - 1; i >= 0; i--) {
        if (dir[i] == '/') {
            break;
        }
    }    

    if (i < 0) { 
        return dir; 
    }    

    char *result = strdup_s(&dir[i + 1]); 
    free(dir);
    return result;
}

inline bool abspath(const char *str) {
	return *str == '/';
}

int safe_int(const char *numstr, int *converted) {
	char *err = NULL;
	signed long int sli;

	errno = 0;
	sli = strtol(numstr, &err, 0);
    if (errno == ERANGE && (sli == LONG_MAX || sli == LONG_MIN))
        return -ERANGE;

    if (errno != 0 && sli == 0)
        return -EINVAL;

    if (err == numstr || *err != '\0')
        return -EINVAL;

    if (sli > INT_MAX || sli < INT_MIN)
        return -ERANGE;

    *converted = (int)sli;
	return 0;
}

int safe_llong(const char *numstr, long long *converted)
{
    char *err_str = NULL;
    long long ll; 

    if (numstr == NULL || converted == NULL) {
        return -EINVAL;
    }   

    errno = 0;
    ll = strtoll(numstr, &err_str, 0); 
    if (errno > 0) {
        return -errno;
    }   

    *converted = (long long)ll;
    return 0;
}

int safe_strtod(const char *numstr, double *converted)
{
    char *err_str = NULL;
    double ld; 

    if (numstr == NULL || converted == NULL) {
        return -EINVAL;
    }   

    errno = 0;
    ld = strtod(numstr, &err_str);
    if (errno > 0) {
        return -errno;
    }   

    *converted = ld; 
    return 0;
}

static int parse_unit_multiple(const char *unit, int64_t *mltpl) {
	size_t i;
	if(unit[0] == '\0') {
		*mltpl = 1;
		return 0;
	}

	for(i = 0; i < g_unit_map_len; i++) {
		if(strcasecmp(unit, g_unit_map[i].name) == 0) {
			*mltpl = g_unit_map[i].mltpl;
			return 0;
		}
	}
	return -EINVAL;
}

int parse_size_int_and_float(const char *numstr, int64_t mlt, int64_t *converted)
{
    long long int_size = 0;
    double float_size = 0;
    long long int_real = 0;
    long long float_real = 0;
    char *dot = NULL;
    int nret;

    dot = strchr(numstr, '.');
    if (dot != NULL) {
        char tmp;
        // interger.float
        if (dot == numstr || *(dot + 1) == '\0') {
            return -EINVAL;
        }
        // replace 123.456 to 120.456
        tmp = *(dot - 1);
        *(dot - 1) = '0';
        // parsing 0.456
        nret = safe_strtod(dot - 1, &float_size);
        // recover 120.456 to 123.456
        *(dot - 1) = tmp;
        if (nret < 0) {
            return nret;
        }
        float_real = (int64_t)float_size;
        if (mlt > 0) {
            if (INT64_MAX / mlt < (int64_t)float_size) {
                return -ERANGE;
            }
            float_real = (int64_t)(float_size * mlt);
        }
        *dot = '\0';
    }
    nret = safe_llong(numstr, &int_size);
    if (nret < 0) {
        return nret;
    }
    int_real = int_size;
    if (mlt > 0) {
        if (INT64_MAX / mlt < int_size) {
            return -ERANGE;
        }
        int_real = int_size * mlt;
    }
    if (INT64_MAX - int_real < float_real) {
        return -ERANGE;
    }

    *converted = int_real + float_real;
    return 0;
}

int parse_byte_size_string(const char *s, int64_t *converted)
{
    int ret;
    int64_t mltpl = 0;
    char *dup = NULL;
    char *pmlt = NULL;

    if (s == NULL || converted == NULL || s[0] == '\0' || !isdigit(s[0])) {
        return -EINVAL;
    }   

    dup = strdup_s(s);
    if (dup == NULL) {
        return -ENOMEM;
    }   

    pmlt = dup;
    while (*pmlt != '\0' && (isdigit(*pmlt) || *pmlt == '.')) {
        pmlt++;
    }   

    ret = parse_unit_multiple(pmlt, &mltpl);
    if (ret) {
        free(dup);
        return ret;
    }   

    // replace the first multiple arg to '\0'
    *pmlt = '\0';
    ret = parse_size_int_and_float(dup, mltpl, converted);
    free(dup);
    return ret;
}

int generate_random_str(char *id, size_t len) {
	int fd = -1;
	int num = 0;
	size_t i;
	const int m = 256;

	len = len / 2;
	fd = open("/dev/urandom", O_RDONLY);
	if(fd == -1) {
		LOG_ERROR("Failed to open /dev/urandom\n");
		return -1;
	}

	for(i = 0; i < len; i++) {
		int nret;
		if(read_nointr(fd, &num, sizeof(int)) < 0) {
			LOG_ERROR("Failed to read urandom value\n");
			close(fd);
			return -1;
		}
		unsigned char rs = (unsigned char)(num % m);
		nret = snprintf((id + i * 2), ((len - i) * 2 + 1), "%02x", (unsigned int)rs);
		if(nret < 0 || (size_t)nret >= ((len - i) * 2 + 1)) {
			LOG_ERROR("Failed to snprintf random string\n");
			close(fd);
			return -1;
		}
	}
	close(fd);
	id[i*2] = '\0';
	return 0;
}

static char **make_empty_array() {
	char **res_array = NULL;
	res_array = calloc(2, sizeof(char*));
	if(res_array == NULL) {
		return NULL;
	}
	res_array[0] = strdup_s("");
	return res_array;
}

void free_array_by_len(char **array, size_t len) {
	size_t i = 0;
	if(array == NULL) {
		return;
	}
	for(; i < len; i++) {
		free((void*)array[i]);
		array[i] = NULL;
	}
	free(array);
}

void free_array(char **array) {
	char **p;
	for(p = array; p != NULL && *p != NULL; p++) {
		free((void*)*p);
		*p = NULL;
	}
	free(array);
}

static char *do_string_join(const char *sep, const char **parts, size_t parts_len, size_t result_len)
{
    char *res_string = NULL;
    size_t iter;

    res_string = calloc_s(result_len + 1, sizeof(char)); 
    if (res_string == NULL) {
        return NULL;
    }   

    for (iter = 0; iter < parts_len - 1; iter++) {
        (void)strcat(res_string, parts[iter]);
        (void)strcat(res_string, sep);
    }   
    (void)strcat(res_string, parts[parts_len - 1]);
    return res_string;
}

char *string_join(const char *sep, const char **parts, size_t len)
{
    size_t sep_len;
    size_t result_len;
    size_t iter;

    if (len == 0 || parts == NULL || sep == NULL) {
        return NULL;
    }

    sep_len = strlen(sep);

    if ((sep_len != 0) && (sep_len != 1) && (len > SIZE_MAX / sep_len + 1)) {
        return NULL;
    }
    result_len = (len - 1) * sep_len;
    for (iter = 0; iter < len; iter++) {
        if (parts[iter] == NULL || result_len >= SIZE_MAX - strlen(parts[iter])) {
            return NULL;
        }
        result_len += strlen(parts[iter]);
    }

    return do_string_join(sep, parts, len, result_len);
}

char *string_append(const char *post, const char *pre)
{
    char *res_string = NULL;
    size_t length = 0;

    if (post == NULL && pre == NULL) {
        return NULL;
    }   
    if (pre == NULL) {
        return strdup_s(post);
    }   
    if (post == NULL) {
        return strdup_s(pre);
    }   
    if (strlen(post) > ((SIZE_MAX - strlen(pre)) - 1)) {
    	LOG_ERROR("String is too long to be appended\n");
        return NULL;
    }   
    length = strlen(post) + strlen(pre) + 1;
    res_string = common_calloc_s(length);
    if (res_string == NULL) {
        return NULL;
    }   
    (void)strcat(res_string, pre);
    (void)strcat(res_string, post);

    return res_string;
}

char **string_split(const char *src_str, char _sep, int *nlen)
{
    char *token = NULL;
    char *str = NULL;
    char *tmpstr = NULL;
    char *reserve_ptr = NULL;
    char deli[2] = { _sep, '\0' };
    char **res_array = NULL;
    size_t capacity = 0;
    size_t count = 0;
    int ret, tmp_errno;

    if (src_str == NULL) {
        return NULL;
    }
    if (src_str[0] == '\0') {
        return make_empty_array();
    }

    tmpstr = strdup_s(src_str);

    str = tmpstr;
    for (; (token = strtok(str, deli)); str = NULL) {
        //ret = grow_array(&res_array, &capacity, count + 1, 16);
		res_array = (char**)realloc(res_array, (capacity + 1) * sizeof(char*));
        if (res_array == NULL) {
            goto err_out;
        }
        res_array[count] = strdup_s(token);
        count++;
		capacity++;
    }
    if (res_array == NULL) {
        free(tmpstr);
        return make_empty_array();
    }
	*nlen = count;
    free(tmpstr);
    return res_array;

err_out:
    tmp_errno = errno;
    free(tmpstr);
    free_array_by_len(res_array, count);
    errno = tmp_errno;
	*nlen = 0;
    return NULL;
}

char *strdup_s(const char* src) {
	char* dst = NULL;
	if(src == NULL) {
		return  NULL;
	}
	dst = strdup(src);
	if(dst == NULL) {
		abort();
	}
	return dst;
}

bool file_exists(const char* f) {
	struct stat buf;
	int nret;
	if(f == NULL) {
		return false;
	}
	nret = stat(f, &buf);
	if(nret < 0) {
		return false;
	}
	return true;
}

void* calloc_s(size_t unit_size, size_t count) {
	if(unit_size == 0) {
		return NULL;
	}
	if(count > (MAX_MEMORY_SIZE / unit_size)) {
		return NULL;
	}
	return calloc(count, unit_size);
}

void *common_calloc_s(size_t size)
{
    if (size == 0 || size > MAX_MEMORY_SIZE) {
        return NULL;
    }    

    return calloc((size_t)1, size);
}

size_t array_len(const char** array) {
	const char** pos;
	size_t len = 0;
	for(pos = array; pos != NULL && *pos != NULL; pos++) {
		len++;
	}
	return len;
}

char** str_array_dup(const char** src, size_t len) {
	size_t i;
	char** dest = NULL;
	if(len == 0 || src == NULL) {
		return NULL;
	}
	dest = (char**)calloc(1, sizeof(char*) * (len + 1));
	if(dest == NULL) 
		return NULL;
	for(i = 0; i < len; i++) {
		if(src[i] != NULL)
			dest[i] = strdup_s(src[i]);
	}
	return dest;
}

bool has_prefix(const char* str, const char* prefix) {
	if(str == NULL || prefix == NULL)
		return false;
	if(strlen(str) < strlen(prefix))
		return false;
	if(strncmp(str, prefix, strlen(prefix)) != 0) {
		return false;
	}
	return true;
}

bool has_suffix(const char* str, const char* suffix) {
	size_t str_len = 0;
	size_t suffix_len = 0;
	if(str == NULL || suffix == NULL)
		return false;
	str_len = strlen(str);
	suffix_len = strlen(suffix);
	if(str_len < suffix_len) {
		return false;
	}
	if(strcmp(str + str_len - suffix_len, suffix) != 0)
		return false;
	return true;
}

char* read_text_file(const char* path) {
	char* buf = NULL;
	long len = 0;
	size_t readlen = 0;
	FILE* filp = NULL;
	const long max_size = 10 * 1024 * 1024;
	if(path == NULL) {
		LOG_ERROR("invalid NULL param");
		return NULL;
	}
	filp = fopen(path, "r");
	if(filp == NULL) {
		LOG_ERROR("open file %s failed", path);
		goto err_out;
	}
	if(fseek(filp, 0, SEEK_END)) {
		LOG_ERROR("Seek end failed");
		goto err_out;
	}
	len = ftell(filp);
	if(len > max_size) {
		LOG_ERROR("File too large");
		goto err_out;
	}
	if(fseek(filp, 0, SEEK_SET)) {
		LOG_ERROR("Seek set failed");
		goto err_out;
	}
	buf = (char*)calloc(1, (len + 1));
	if(buf == NULL) {
		LOG_ERROR("Out of memory");
		goto err_out;
	}
	readlen = fread(buf, 1, (size_t)len, filp);
	if(((readlen < (size_t)len) && (!feof(filp))) || (readlen > (size_t)len)) {
		LOG_ERROR("failed to read file %s, error: %s", path, strerror(errno));
		free(buf);
		goto err_out;
	}
	buf[(size_t)len] = 0;
err_out:
	if(filp != NULL) {
		fclose(filp);
	}
	return buf;
}

int write_file(const char* fname, const char* content, size_t content_len, mode_t mode) {
	int ret = 0;
	int dst_fd = -1;
	ssize_t len = 0;
	if(fname == NULL)
		return -1;
	if(content == NULL || content_len == 0)
		return 0;
	dst_fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if(dst_fd < 0) {
		LOG_ERROR("create file: %s, failed: %s", fname, strerror(errno));
		ret = -1;
		goto free_out;
	}
	for(;;) {
		len = write(dst_fd, content, content_len);
		if(len < 0 && errno == EINTR)
			continue;
		else
			break;
	}
	if(len < 0 || len != content_len) {
		ret = -1;
		LOG_ERROR("write file failed: %s", strerror(errno));
		goto free_out;
	}
free_out:
	if(dst_fd >= 0) 
		close(dst_fd);
	return ret;
}

ssize_t write_nointr(int fd, const void *buf, size_t count)
{
    ssize_t nret;

    if (buf == NULL) {
        return -1;
    }    

    for (;;) {
        nret = write(fd, buf, count);
        if (nret < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }    
    return nret;
}

ssize_t read_nointr(int fd, void *buf, size_t count)
{
    ssize_t nret;

    if (buf == NULL) {
        return -1;
    }    

    for (;;) {
        nret = read(fd, buf, count);
        if (nret < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    return nret;
}

static char *get_random_tmp_file(const char *fname)
{
#define RANDOM_TMP_PATH 10
    int nret = 0;
    char *result = NULL;
    char *base = NULL;
    char *dir = NULL;
    char rpath[PATH_MAX] = { 0x00 };
    char random_tmp[RANDOM_TMP_PATH + 1] = { 0x00 };

    base = path_base(fname);
    if (base == NULL) {
    	LOG_ERROR("Failed to get base of %s\n", fname);
        goto out;
    }

    dir = path_dir(fname);
    if (dir == NULL) {
    	LOG_ERROR("Failed to get dir of %s\n", fname);
        goto out;
    }

    if (generate_random_str(random_tmp, (size_t)RANDOM_TMP_PATH)) {
    	LOG_ERROR("Failed to generate random str for random path\n");
        goto out;
    }

    nret = snprintf(rpath, PATH_MAX, ".tmp-%s-%s", base, random_tmp);
    if (nret < 0 || nret >= PATH_MAX) {
    	LOG_ERROR("Failed to generate tmp base file\n");
        goto out;
    }

    result = path_join(dir, rpath);

out:
    free(base);
    free(dir);
    return result;
}

static int do_atomic_write_file(const char *fname, const char *content, size_t content_len, mode_t mode, bool sync)
{
    int ret = 0;
    int dst_fd = -1;
    ssize_t len = 0;

    dst_fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (dst_fd < 0) {
    	LOG_ERROR("Creat file: %s, failed: %s\n", fname, strerror(errno));
        ret = -1;
        goto free_out;
    }

    len = write_nointr(dst_fd, content, content_len);
    if (len < 0 || ((size_t)len) != content_len) {
        ret = -1;
    	LOG_ERROR("Write file failed: %s\n", strerror(errno));
        goto free_out;
    }

    /*if (sync && (fdatasync(dst_fd) != 0)) {
        ret = -1;
        SYSERROR("Failed to sync data of file:%s", fname);
        goto free_out;
    }*/

free_out:
    if (dst_fd >= 0) {
        close(dst_fd);
    }
    return ret;
}

int atomic_write_file(const char *fname, const char *content, size_t content_len, mode_t mode, bool sync)
{
    int ret = 0; 
    char *tmp_file = NULL;
    char rpath[PATH_MAX] = { 0x00 };

    if (fname == NULL) {
        return -1;
    }    
    if (content == NULL || content_len == 0) { 
        return 0;
    }    

    if (clean_path(fname, rpath, sizeof(rpath)) == NULL) {
        return -1;
    }    

    tmp_file = get_random_tmp_file(fname);
    if (tmp_file == NULL) {
    	LOG_ERROR("Failed to get tmp file for %s\n", fname);
        return -1;
    }    

    ret = do_atomic_write_file(tmp_file, content, content_len, mode, sync);
    if (ret != 0) { 
    	LOG_ERROR("Failed to write content to tmp file for %s\n", tmp_file);
        ret = -1;
        goto free_out;
    }    

    ret = rename(tmp_file, rpath);
    if (ret != 0) { 
    	LOG_ERROR("Failed to rename old file %s to target %s\n", tmp_file, rpath);
        ret = -1;
        goto free_out;
    }    

free_out:
    if (ret != 0 && unlink(tmp_file) != 0 && errno != ENOENT) {
    	LOG_ERROR("Failed to remove temp file:%s\n", tmp_file);
    }    
    free(tmp_file);
    return ret; 
}

int array_append(char*** array, const char* element) {
	size_t len;
	char** new_array = NULL;
	if(array == NULL || element == NULL) {
		return -1;
	}
	len = array_len((const char**)(*array));
	new_array = calloc_s(sizeof(char*), (len + 2));
	if(new_array == NULL) {
		LOG_ERROR("Out of memory\n");
		return -1;
	}
	if(*array != NULL) {
		(void)memcpy(new_array, *array, len * sizeof(char*));
		do {
			if((*array) != NULL) {
				free((void*)(*array));
				(*array) = NULL;
			}	
		} while(0);
	}
	*array = new_array;
	new_array[len] = strdup_s(element);
	return 0;
}

static void normalized_host_arch(char **host_arch, struct utsname uts)
{
    const char *arch_map[][2] = { { "i386", "386" },
        { "x86_64", "amd64" },
        { "x86-64", "amd64" },
        { "aarch64", "arm64" },
        { "armhf", "arm" },
        { "armel", "arm" },
        { "mips64le", "mips64le" },
        { "mips64el", "mips64le" }
    };
    int i = 0;

    *host_arch = strdup_s(uts.machine);

    for (i = 0; i < sizeof(arch_map) / sizeof(arch_map[0]); ++i) {
        if (strcasecmp(uts.machine, arch_map[i][0]) == 0) {
            free(*host_arch);
            *host_arch = strdup_s(arch_map[i][1]);
            break;
        }
    }
}

bool dir_exists(const char* path) {
	struct stat s;
	int nret;
	if(path == NULL)
		return false;
	nret = stat(path, &s);
	if(nret < 0) {
		return false;
	}
	return S_ISDIR(s.st_mode);
}

int scan_subdirs(const char *directory, subdir_callback_t cb, void *context) {
	DIR *dir = NULL;
	struct dirent *direntp = NULL;
	int ret = 0;

	if(directory == NULL || cb == NULL) {
		return -1;
	}

	dir = opendir(directory);
	if(dir == NULL) {
		LOG_ERROR("Failed to open directory: %s error:%s\n", directory, strerror(errno));
		return -1;
	}

	direntp = readdir(dir);
	for(; direntp != NULL; direntp = readdir(dir)) {
		if(strcmp(direntp->d_name, ".") == 0 || strcmp(direntp->d_name, "..") == 0) {
			continue;
		}

		if(!cb(directory, direntp, context)) {
			LOG_ERROR("Dealwith subdir : %s failed\n", direntp->d_name);
			ret = -1;
			break;
		}
	}

	closedir(dir);
	return ret;
}

int mkdir_p(const char* dir, mode_t mode) {
	const char* tmp_pos = NULL;
	const char* base = NULL;
	char* cur_dir = NULL;
	int len = 0;
	uid_t host_uid = 0;
	gid_t host_gid = 0;
	unsigned int size = 0;
	int ret = 0;
	if(dir == NULL || strlen(dir) > PATH_MAX || strlen(dir) <= 0) {
		goto err_out;
	}
	
	tmp_pos = dir;
	base = dir;
	do {
		dir = tmp_pos + strspn(tmp_pos, "/");
		tmp_pos = dir + strcspn(dir, "/");
		len = (int)(dir - base);
		if(len <= 0) {
			break;
		}
		cur_dir = strndup(base, (size_t)len);
		if(cur_dir == NULL) {
			goto err_out;
		}
		if(*cur_dir) {
			ret = mkdir(cur_dir, mode);
			if(ret != 0 && (errno != EEXIST || !dir_exists(cur_dir))) {
				LOG_ERROR("mkdir err!\n");
				goto err_out;
			}
		}
		free(cur_dir);
		cur_dir = NULL;
	} while(tmp_pos != dir);
	if(chmod(base, mode) != 0) {
		goto err_out;
	} 
	return 0;
err_out:
	if(cur_dir != NULL)
		free(cur_dir);
	return -1;
}

size_t strlncat(char *dststr, size_t size, const char *srcstr, size_t nsize)
{
    size_t ssize, dsize;

    ssize = (size_t)strnlen(srcstr, nsize);
    dsize = (size_t)strnlen(dststr, size);

    if (dsize < size) {
        size_t rsize = size - dsize;
        size_t ncpy = ssize < rsize ? ssize : (rsize - 1); 
        memcpy(dststr + dsize, srcstr, ncpy);
        dststr[dsize + ncpy] = '\0';
    }   
	//printf("%s\n", dststr);
    return ssize + dsize;
}

Buffer *buffer_alloc(size_t initial_size)
{
    Buffer *buf = NULL;
    char *tmp = NULL;

    if (initial_size == 0) {
        return NULL;
    }   

    buf = calloc_s(1, sizeof(Buffer));
    if (buf == NULL) {
        return NULL;
    }   

    if (initial_size > SIZE_MAX / sizeof(char)) {
        free(buf);
        return NULL;
    }   
    tmp = calloc(1, initial_size * sizeof(char));
    if (tmp == NULL) {
        free(buf);
        return NULL;
    }   

    buf->contents = tmp;
    buf->bytes_used = 0;
    buf->total_size = initial_size;

    return buf;
}

void buffer_free(Buffer* buf) {
	if(buf == NULL)
		return;
	free(buf->contents);
	buf->contents = NULL;
	free(buf);
}

int buffer_grow(Buffer *buffer, size_t min_size)
{
    size_t factor = 0;
    size_t new_size = 0;
    char *tmp = NULL;

    if (buffer == NULL) {
        return -1;
    }

    factor = buffer->total_size;
    if (factor < min_size) {
        factor = min_size;
    }
    if (factor > SIZE_MAX / 2) {
        return -1;
    }
    new_size = factor * 2;
    if (new_size == 0) {
        return -1;
    }

    tmp = common_calloc_s(new_size);
    if (tmp == NULL) {
    	LOG_ERROR("Out of memory");
        return -1;
    }

    (void)memcpy(tmp, buffer->contents, buffer->total_size);

    (void)memset(buffer->contents, 0, buffer->total_size);

    free(buffer->contents);
    buffer->contents = tmp;
    buffer->total_size = new_size;

    return 0;
}

int buffer_append(Buffer *buf, const char *append, size_t len)
{
    size_t desired_length = 0;
    size_t i = 0;
    size_t bytes_copy = 0;

    if (buf == NULL) {
        return -1; 
    }   

    desired_length = len + 1;
    if ((buf->total_size - buf->bytes_used) < desired_length) {
        int status = buffer_grow(buf, desired_length);
        if (status != 0) {
            return -1; 
        }
    }   

    for (i = 0; i < len; i++) {
        if (append[i] == '\0') {
            break;
        }

        size_t pos = buf->bytes_used + i;
        *(buf->contents + pos) = append[i];

        bytes_copy++;
    }   

    buf->bytes_used += bytes_copy;
    /* string end */
    *(buf->contents + buf->bytes_used) = '\0';

    return 0;
}

int dup_array_of_strings(const char** src, size_t src_len, char*** dst, size_t* dst_len) {
	size_t i;

	if(src == NULL || src_len == 0) {
		return 0;
	}

	if(dst == NULL || dst_len == NULL) {
		return -1;
	}

	*dst = NULL;
	*dst_len = 0;
	*dst = (char**)calloc_s(sizeof(char*), src_len);
	if(*dst == NULL) {
		LOG_ERROR("Out of memory\n");
		return -1;
	}
	for(i = 0; i < src_len; i++) {
		(*dst)[*dst_len] = (src[i] != NULL) ? strdup_s(src[i]) : NULL;
		(*dst_len)++;
	}
	return 0;
}

int mem_realloc(void** newptr, size_t newsize, void* oldptr, size_t oldsize) {
	void* tmp = NULL;
	
	if(newptr == NULL || newsize == 0) {
		return -1;
	}

	tmp = calloc_s(1, newsize);
	if(tmp == NULL) {
		LOG_ERROR("Failed to malloc memory\n");
		return -1;
	}

	if(oldptr != NULL) {
		memcpy(tmp, oldptr, (newsize < oldsize) ? newsize : oldsize);
		memset(oldptr, 0, oldsize);
		free(oldptr);
	}

	*newptr = tmp;
	return 0;
}

int reg_match(const char *patten, const char *str)
{
    int nret = 0;
    char buffer[EVENT_ARGS_MAX] = { 0 };
    regex_t reg;

    if (patten == NULL || str == NULL) {
    	LOG_ERROR("invalid NULL param");
        return -1; 
    }   

    nret = regcomp(&reg, patten, REG_EXTENDED | REG_NOSUB);
    if (nret != 0) {
        regerror(nret, &reg, buffer, EVENT_ARGS_MAX);
    	LOG_ERROR("regcomp %s failed: %s", patten, buffer);
        return -1; 
    }   

    nret = regexec(&reg, str, 0, NULL, 0); 
    if (nret == 0) {
        nret = 0;
        goto free_out;
    } else if (nret == REG_NOMATCH) {
        nret = 1;
        goto free_out;
    } else {
        nret = -1; 
    	LOG_ERROR("reg match failed");
        goto free_out;
    }   

free_out:
    regfree(&reg);

    return nret;
}

bool strings_contains_any(const char *str, const char *substr)
{
    size_t i = 0;
    size_t j;
    size_t len_str = 0;
    size_t len_substr = 0;

    if (str == NULL || substr == NULL) {
        return false;
    }   

    len_str = strlen(str);
    len_substr = strlen(substr);

    for (i = 0; i < len_str; i++) {
        for (j = 0; j < len_substr; j++) {
            if (str[i] == substr[j]) {
                return true;
            }
        }
    }   
    return false;
}

int strings_count(const char *str, unsigned char c)
{
    size_t i = 0;
    int res = 0;
    size_t len = 0;

    if (str == NULL) {
        return 0;
    }

    len = strlen(str);
    for (i = 0; i < len; i++) {
        if (str[i] == c) {
            res++;
        }
    }
    return res;
}

static bool check_dir_valid(const char *dirpath, int recursive_depth, int *failure)
{
    if ((recursive_depth + 1) > 31998) {
    	LOG_ERROR("Reach max path depth: %s\n", dirpath);
        *failure = 1;
        return false;
    }

    if (!dir_exists(dirpath)) {
        return false;
    }

    return true;
}

static int mark_file_mutable(const char *fname)
{
    int ret = 0; 
    int fd = -EBADF;
    int attributes = 0; 

    fd = open(fname, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { 
    	LOG_ERROR("Failed to open file to modify flags:%s\n", fname);
        return -1;
    }    

    if (ioctl(fd, FS_IOC_GETFLAGS, &attributes) < 0) { 
    	LOG_ERROR("Failed to retrieve file flags\n");
        ret = -1;
        goto out; 
    }    

    attributes &= ~FS_IMMUTABLE_FL;

    if (ioctl(fd, FS_IOC_SETFLAGS, &attributes) < 0) { 
    	LOG_ERROR("Failed to set file flags\n");
        ret = -1;
        goto out; 
    }    

out:
    if (fd >= 0) { 
        close(fd);
    }    
    return ret; 
}

static bool force_remove_file(const char *fname, int *saved_errno) {
	if(unlink(fname) == 0) {
		return true;
	}

	if(*saved_errno == 0) {
		*saved_errno = errno;
	}

	if(mark_file_mutable(fname) != 0) {
		LOG_ERROR("Failed to mark file mutable\n");
	}

	if(unlink(fname) != 0) {
		LOG_ERROR("Failed to delete %s : %s\n", fname, strerror(errno));
		return false;
	}

	return true; 
}

static int recursive_rmdir_next_depth(struct stat fstat, const char *fname, int recursive_depth, int *saved_errno,
                                      int failure)
{
    if (S_ISDIR(fstat.st_mode)) {
        if (recursive_rmdir(fname, (recursive_depth + 1)) < 0) {
            failure = 1;
        }
    } else {
        failure = force_remove_file(fname, saved_errno) ? 0 : 1;
    }

    return failure;
}

static int recursive_rmdir_helper(const char *dirpath, int recursive_depth, int *saved_errno)
{
    int nret = 0;
    struct dirent *pdirent = NULL;
    DIR *directory = NULL;
    int failure = 0;
    char fname[PATH_MAX];

    directory = opendir(dirpath);
    if (directory == NULL) {
    	LOG_ERROR("Failed to open %s\n", dirpath);
        return 1;
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
            failure = 1;
            continue;
        }

        nret = lstat(fname, &fstat);
        if (nret) {
        	LOG_ERROR("Failed to stat %s\n", fname);
            failure = 1;
            continue;
        }

        failure = recursive_rmdir_next_depth(fstat, fname, recursive_depth, saved_errno, failure);
    }

    if (rmdir(dirpath) < 0 && errno != ENOENT) {
        if (*saved_errno == 0) {
            *saved_errno = errno;
        }
    	LOG_ERROR("Failed to delete %s\n", dirpath);
        failure = 1;
    }

    nret = closedir(directory);
    if (nret) {
    	LOG_ERROR("Failed to close directory %s\n", dirpath);
        failure = 1;
    }

    return failure;
}

int recursive_rmdir(const char *dirpath, int recursive_depth)
{
    int failure = 0;
    int saved_errno = 0;

    if (dirpath == NULL) {
        return -1;
    }

    if (!check_dir_valid(dirpath, recursive_depth, &failure)) {
        goto err_out;
    }

    failure = recursive_rmdir_helper(dirpath, recursive_depth, &saved_errno);
    if (failure != 0) {
    	LOG_ERROR("Recursive delete dir failed. Try delete forcely with command\n");
        /*failure = exec_force_rmdir_command(dirpath);
        if (failure != 0) {
            ERROR("Recursive delete dir forcely with command failed");
        }*/
    }

err_out:
    errno = saved_errno;
    return failure ? -1 : 0;
}

int recursive_remove_path(const char *path) {
	int ret = 0;
	if(unlink(path) != 0 && errno != ENOENT) {
		ret = recursive_rmdir(path, 0);
	}
	return ret;
}

int wait_for_pid(pid_t pid) {
	int st;
	int nret = 0;
rep:
	nret = waitpid(pid, &st, 0);
	if(nret == -1) {
		if(errno == EINTR) {
			goto rep;
		}
		return -1;
	}
	if(nret != pid) {
		goto rep;
	}
	if(!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		return -1;
	}
	return 0;
}

int wait_for_pid_status(pid_t pid) {
	int st;
	int nret = 0;
rep:
	nret = waitpid(pid, &st, 0);
	if(nret == -1) {
		if(errno == EINTR) {
			goto rep;
		}
		return -1;
	}
	if(nret != pid) {
		goto rep;
	}
	return st;
}

#define BLKSIZE 32768
// Compress
int gzip_z(const char *srcfile, const char *dstfile, const mode_t mode)
{
    int ret = 0;
    int srcfd = 0;
    gzFile stream = NULL;
    ssize_t size = 0;
    size_t n = 0;
    void *buffer = 0;
    const char *gzerr = NULL;
    int errnum = 0;

    srcfd = open(srcfile, O_RDONLY, 0644);
    if (srcfd < 0) {
    	LOG_ERROR("Open src file: %s, failed: %s", srcfile, strerror(errno));
        return -1; 
    }   

    stream = gzopen(dstfile, "w");
    if (stream == NULL) {
    	LOG_ERROR("gzopen %s error: %s", dstfile, strerror(errno));
        close(srcfd);
        return -1; 
    }   

    buffer = calloc_s(1, BLKSIZE);
    if (buffer == NULL) {
    	LOG_ERROR("out of memory");
        ret = -1; 
        goto out;
    }   

    while (true) {
        size = read_nointr(srcfd, buffer, BLKSIZE);
        if (size < 0) {
        	LOG_ERROR("read file %s failed: %s", srcfile, strerror(errno));
            ret = -1; 
            break;
        } else if (size == 0) {
            break;
        }

        n = gzwrite(stream, buffer, size);
        if (n <= 0 || n != (size_t)size) {
            gzerr = gzerror(stream, &errnum);
            if (gzerr != NULL && strcmp(gzerr, "") != 0) {
            	LOG_ERROR("gzread error: %s", gzerr);
            }
            ret = -1;
            break;
        }
    }
    if (chmod(dstfile, mode) != 0) {
    	LOG_ERROR("Change mode of tar-split file");
        ret = -1;
    }

out:
    gzclose(stream);
    close(srcfd);
    free(buffer);
    if (ret != 0) {
        if (path_remove(dstfile) != 0) {
        	LOG_ERROR("Remove file %s failed: %s", dstfile, strerror(errno));
        }
    }

    return ret;
}

static char *get_last_part(char **parts)
{
    char *last_part = NULL;
    char **p;

    for (p = parts; p != NULL && *p != NULL; p++) {
        last_part = *p; 
    }   

    return last_part;
}

#define DEFAULT_TAG ":latest"
char *oci_default_tag(const char *name)
{
    char temp[PATH_MAX] = { 0 };
    char **parts = NULL;
    char *last_part = NULL;
    char *add_default_tag = "";
	int nlen = 0;

    if (name == NULL) {
    	LOG_ERROR("Invalid NULL param");
        return NULL;
    }

    parts = string_split(name, '/', &nlen);
    if (parts == NULL) {
    	LOG_ERROR("split %s by '/' failed", name);
        return NULL;
    }

    last_part = parts[nlen-1];
    // will pass image name with digest and with tag
    if (last_part != NULL && strrchr(last_part, ':') == NULL) {
        add_default_tag = DEFAULT_TAG;
    }

    free_array_by_len(parts, nlen);

    // Add image's default tag
    int nret = snprintf(temp, sizeof(temp), "%s%s", name, add_default_tag);
    if (nret < 0 || (size_t)nret >= sizeof(temp)) {
    	LOG_ERROR("sprint temp image name failed");
        return NULL;
    }

    return strdup_s(temp);
}

#define REPO_PREFIX_TO_STRIP "library/"
char *oci_add_host(const char *host, const char *name) {
	char *with_host = NULL;
	bool need_repo_prefix = false;

	if(host == NULL || name == NULL) {
		LOG_ERROR("Invalid NULL param");
		return NULL;
	}
	
	if(strlen(host) == 0) {
		LOG_ERROR("Invalid host");
		return NULL;
	}

	if(strchr(name, '/') == NULL) {
		need_repo_prefix = true;
	}

	with_host = common_calloc_s(strlen(host) + strlen("/") + strlen(REPO_PREFIX_TO_STRIP) + strlen(name) + 1);
	if(with_host == NULL) {
		LOG_ERROR("out of memory");
		return NULL;
	}
	strcat(with_host, host);
	if(host[strlen(host) - 1] != '/') {
		strcat(with_host, "/");
	}
	if(need_repo_prefix) {
		strcat(with_host, REPO_PREFIX_TO_STRIP);
	}
	strcat(with_host, name);

	return with_host;
}

char *oci_normalize_image_name(const char *name)
{
    char *with_tag = oci_default_tag(name);
    //char *result = NULL;

    //result = oci_strip_host_prefix(with_tag);
    //free(with_tag);

    return with_tag;
}

static char *tag_pos(const char *ref) {
	char *tag_pos = NULL;

	if(ref == NULL) {
		return NULL;
	}

	tag_pos = strrchr(ref, ':');
	if(tag_pos != NULL) {
		if(strchr(tag_pos, '/') == NULL) {
			return tag_pos;
		}
	}

	return NULL;
}

bool valid_image_name(const char *name) {
	char *copy = NULL;
	char *check_pos = NULL;
	bool bret = false;

	if(name == NULL) {
		LOG_ERROR("invalid NULL param");
		return false;
	}

	if(strnlen(name, MAX_IMAGE_NAME_LEN + 1) > MAX_IMAGE_NAME_LEN) {
		return false;
	}

	copy = strdup_s(name);

	check_pos = strrchr(copy, '@');
	if(check_pos != NULL) {
		if(reg_match(__DIGESTPattern, check_pos)) {
			goto cleanup;
		}
		*check_pos = '\0';
	} else {
		check_pos = tag_pos(copy);
		if(check_pos != NULL) {
			if(reg_match(__TagPattern, check_pos)) {
				goto cleanup;
			}
			*check_pos = '\0';
		}
	}
	
	if(reg_match(__NamePattern, copy)) {
		goto cleanup;
	}
	bret = true;

cleanup:
	free(copy);
	return bret;
}

int open_devnull() {
	int fd = open("/dev/null", O_RDWR);
	if(fd < 0) {
		LOG_ERROR("Can't open /dev/null");
	}

	return fd;
}

int set_stdfds(int fd) {
	int ret = 0;

	if(fd < 0) {
		return -1;
	}

	ret = dup2(fd, STDIN_FILENO);
	if(ret < 0) {
		return -1;
	}

	ret = dup2(fd, STDOUT_FILENO);
	if(ret < 0) {
		return -1;
	}

	ret = dup2(fd, STDERR_FILENO);
	if(ret < 0) {
		return -1;
	}

	return 0;
}

int null_stdfds() {
	int ret = -1;
	int fd = 0;

	fd = open_devnull();
	if(fd >= 0) {
		ret = set_stdfds(fd);
		close(fd);
	}

	return ret;
}
