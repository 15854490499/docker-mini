#include <stdbool>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "registry.h"
#include "../utils/utils.h"
#include "certs.h"
# include <yajl/yajl_tree.h>
# include <yajl/yajl_gen.h>

#ifdef __cplusplus
extern "C" {
#endif

#define define_cleaner_function(type, cleaner)           \
        static inline void cleaner##_function(type *ptr) \
        {                                                \
                if (*ptr)                                \
                        cleaner(*ptr);                   \
        }

#define __auto_cleanup(cleaner) __attribute__((__cleanup__(cleaner##_function)))

typedef struct {
    char *token;

    char *access_token;

    uint32_t expires_in;

    char *issued_at;

    char *refresh_token;

    yajl_val _residual;
} registry_token;

struct parser_context {
	unsigned int options;
	FILE* errfile;
};

int setup_auth_chanllenges(pull_descriptor* desc, char*** custom_headers);
int get_bearer_token(pull_descriptor* desc, challenge* c);
int setup_auth_basic(pull_descriptor* desc, char*** custom_headers);
int http_request_get_token(pull_descriptor *desc, challenge *c, char **output);
int setup_get_token_options(pull_descriptor *desc, struct http_get_options *options, const char *url);
char* build_get_token_url(challenge *c, char *username, char *scope);
char* get_url_host(const char* url);
char* basic_auth_header(const char* schema, const char* username, const char* password);
int setup_ssl_config(pull_descriptor *desc, struct http_get_options *options, const char *url);
int certs_load(char *host, bool use_decrypted_key, char **ca_file, char **cert_file, char **key_file);
char* encode_auth(const char* username, const char* password);
char* auth_header_str(const char* schema, const char* value);

//registry_token* registry_token_parse_data(const char* jsondata, const struct parser_context* ctx, parser_error* err);

#ifdef __cplusplus
}
#endif
