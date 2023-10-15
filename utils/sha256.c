/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide container sha256 functions
 *******************************************************************************/

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "utils.h"
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/ossl_typ.h>
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include "sha256.h"
#include "log.h"
#define BLKSIZE 32768

char* calc_full_digest(const char *digest)
{
    int nret = 0; 
    char full_digest[PATH_MAX] = { 0 }; 

    if (digest == NULL) {
    	LOG_ERROR("invalid NULL digest\n");
        return NULL;
    }    

    nret = snprintf(full_digest, sizeof(full_digest), "%s%s", SHA256_PREFIX, digest);
    if (nret < 0 || (size_t)nret >= sizeof(full_digest)) {
    	LOG_ERROR("digest too long failed\n");
        return NULL;
    }    

    return strdup_s(full_digest);
}


char *sha256_digest_str(const char *val)
{
#if OPENSSL_VERSION_MAJOR < 3
    SHA256_CTX ctx;
#endif
    unsigned char hash[SHA256_DIGEST_LENGTH] = { 0x00 };
    char output_buffer[(SHA256_DIGEST_LENGTH * 2) + 1] = { 0x00 };
    int i = 0;

    if (val == NULL) {
        return NULL;
    }

#if OPENSSL_VERSION_MAJOR >= 3
    SHA256((const unsigned char *)val, strlen(val), hash);
#else
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, val, strlen(val));
    SHA256_Final(hash, &ctx);
#endif

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        int ret = snprintf(output_buffer + (i * 2), 3, "%02x", (unsigned int)hash[i]);
        if (ret >= 3 || ret < 0) {
            return NULL;
        }
    }
    output_buffer[SHA256_DIGEST_LENGTH * 2] = '\0';

    return strdup_s(output_buffer);
}

char* without_sha256_prefix(char* digest) {
	if(digest == NULL) {
		LOG_ERROR("Invalid digest when strip sha256 prefix\n");
		return NULL;
	}
	return digest + strlen(SHA256_PREFIX);
}

static bool should_use_origin_name(const char *name)
{
    size_t i;

    for (i = 0; i < strlen(name); i++) {
        char ch = name[i];
        if (ch != '.' && !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'z')) {
            return false;
        }
    }

    return true;
}

char *make_big_data_base_name(const char *key)
{
    int ret = 0;
    int nret = 0;
    char *b64_encode_name = NULL;
    char *base_name = NULL;
    size_t name_size;
	size_t encoded_size = 0;
    if (should_use_origin_name(key)) {
        return strdup_s(key);
    }   

    //nret = util_base64_encode((unsigned char *)key, strlen(key), &b64_encode_name);
	encoded_size = 65536;//EVP_EncodedLength(&encoded_size, strlen(key));
	b64_encode_name = calloc_s(1, encoded_size);
	if (EVP_EncodeBlock((uint8_t *)(b64_encode_name), (const uint8_t *)key, strlen(key)) == 0) {
    	LOG_ERROR("Encode base64 failed: %s\n", strerror(errno));
        goto out; 
    } 
    if (nret < 0) {
        ret = -1; 
    	LOG_ERROR("Encode auth to base64 failed\n");
        goto out;
    }   
    name_size = 1 + strlen(b64_encode_name) + 1; // '=' + encode string + '\0'

    base_name = (char *)calloc_s(sizeof(char), name_size);
    if (base_name == NULL) {
    	LOG_ERROR("Out of memory\n");
        ret = -1; 
        goto out;
    }   

    nret = snprintf(base_name, name_size, "=%s", b64_encode_name);
    if (nret < 0 || (size_t)nret >= name_size) {
    	LOG_ERROR("Out of memory\n");
        ret = -1; 
        goto out;
    }   

out:
    if (ret != 0) {
        free(base_name);
        base_name = NULL;
    }   
    free(b64_encode_name);

    return base_name;
}
