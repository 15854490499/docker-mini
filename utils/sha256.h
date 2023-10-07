#ifndef UTILS_SHA256_SHA256_H
#define UTILS_SHA256_SHA256_H 

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <zlib.h>

#ifdef __cplusplus
extern "C" {
#endif

//char *sha256_digest_file(const char *filename, bool isgzip);
#define SHA256_PREFIX "sha256:"

char* sha256_digest_str(const char *val);
char* calc_full_digest(const char* digest);
char* without_sha256_prefix(char *digest);
char* make_big_data_base_name(const char *key);
//char *sha256_full_gzip_digest(const char *filename);

//char *sha256_full_file_digest(const char *filename);

//bool sha256_valid_digest_file(const char *path, const char *digest);

//char *sha256_full_digest_str(char *str);

//char *util_without_sha256_prefix(char *digest);

#ifdef __cplusplus
}
#endif

#endif
