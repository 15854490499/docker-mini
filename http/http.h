#ifndef __HTTP_H__
#define __HTTP_H__

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>
#include <curl/curl.h>
#include <http_parser.h>

#include "oci_image_defs_descriptor.h"
#include "oci_image_index.h"
#include "oci_image_manifest.h"
#include "oci_image_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int(*progress_info_func)(void *p, 
                                 double dltotal, double dlnow,
                                 double ultotal, double ulnow);
typedef int(*xferinfo_func)(void *p, 
                            curl_off_t dltotal, curl_off_t dlnow,
                            curl_off_t ultotal, curl_off_t ulnow);

typedef enum {
	HEAD_ONLY = 0,
	BODY_ONLY = 1,
	HEAD_BODY = 2,
	RESUME_BODY = 3,
} resp_data_type;



#define MAX_HEADERS 30
#define MAX_ELEMENT_SIZE 2048
#define MAX_CHUNKS 16
#define MAX_ACCEPT_LEN 128
#define MAX_ID_BUF_LEN 256
/*typedef struct {
	char* schema;
	char* realm;
	char* service;
	char* cached_token;
	time_t expires_time;
} challenge;*/

struct http_get_options {
    unsigned with_head : 1, /* if set, means write output with response HEADER */
             with_body : 1, /* if set, means write output with response BODY */
             /* if set, means set request with "Authorization:(char *)authorization" */
             with_header_auth : 1,
             /* if set, means set request with "Content-Type: application/json" */
             with_header_json : 1,
             /* if set, means set request with "Accept:(char *)accepts" */
             with_header_accept : 1,
             /* if set, means show the process progress" */
             show_progress : 1;

    char outputtype;

    /* if set, means connnect to unix socket */
    char *unix_socket_path;

    /*
     * if outputtype is HTTP_REQUEST_STRBUF, the output is a pointer to struct Buffer
     * if outputtype is HTTP_REQUEST_FILE, the output is a pointer to a file name
     */
    void *output;

    /* http method PUT GET POST */
    void *method;
    /* body to be sent to server */
    void *input;
    size_t input_len;

    char *authorization;

    char *accepts;

    char **custom_headers;

    bool debug;
    bool ssl_verify_peer;
    bool ssl_verify_host;

    char *ca_file;
    char *cert_file;
    char *key_file;

    char *errmsg;
    int errcode;
    bool resume;

    bool timeout;

    void *progressinfo;
    progress_info_func progress_info_op;

    void *xferinfo;
    xferinfo_func xferinfo_op;
};

struct parsed_http_message {
	enum http_method method;
	int status_code;
	char response_status[MAX_ELEMENT_SIZE];
	char request_url[MAX_ELEMENT_SIZE];
	char* body;
	size_t body_size;
	int num_headers;
	enum { NONE = 0, FIELD, VALUE } last_header_element;
	char headers[MAX_HEADERS][2][MAX_ELEMENT_SIZE];
	int should_keep_alive;
	int num_chunks;
	int num_chunks_complete;
	int chunk_lengths[MAX_CHUNKS];
	unsigned short http_major;
    unsigned short http_minor;

    int message_begin_cb_called;
    int headers_complete_cb_called;
    int message_complete_cb_called;
    int status_cb_called;
    int body_is_final;
};

#define HTTP_RES_OK                 0
#define HTTP_RES_MISSING_TARGET     1
#define HTTP_RES_ERROR              2
#define HTTP_RES_START_FAILED       3
#define HTTP_RES_REAUTH             4
#define HTTP_RES_NOAUTH             5
#define status_ok 					200
#define status_unauthorized 		401

/* HTTP Get buffer size */
#define  HTTP_GET_BUFFER_SIZE       65536

/* authz error msg size */
#define  AUTHZ_ERROR_MSG_SIZE       256

/* http_request() targets */
#define HTTP_REQUEST_STRBUF         0
#define HTTP_REQUEST_FILE           1

/* token_expires */
#define MIN_TOKEN_EXPIRES_IN		60

#define BODY_DELIMITER "\r\n\r\n"
struct parsed_http_message* get_parsed_message(char* http_head);
char* get_header_value(const struct parsed_http_message* m, const char* header);
int parse_http_header(const char *http_head, int head_len, struct parsed_http_message *message);

typedef struct _pull_descriptor_ pull_descriptor;

int parse_ping_header(pull_descriptor* desc, char* http_head);
int http_request(const char* url, struct http_get_options* options, long* response_code, int recursive_len);
int http_request_buf(pull_descriptor* desc, const char* url, const char** custom_headers, char** output, resp_data_type type);
int http_request_file(pull_descriptor* desc, const char* url, const char** custom_headers, char* file, resp_data_type type);
void free_http_get_options(struct http_get_options *options);
#ifdef __cplusplus
}
#endif

#endif
