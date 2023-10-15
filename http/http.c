#include <sys/utsname.h>
#include <ctype.h>

#include "http.h"
#include "utils.h"
#include "sha256.h"
#include "registry.h"
#include "storage.h"
#include "log.h"

size_t fwrite_file(const void *ptr, size_t size, size_t nmemb, void *stream) {
	size_t written = fwrite(ptr, size, nmemb, (FILE*)stream);
	return written;
}

size_t fwrite_buffer(const char* ptr, size_t eltsize, size_t nmemb, void* buffer_) {
	size_t size = eltsize * nmemb;
	struct Buffer* buffer = buffer_;
	int status = 0;
	size_t desired_length = size + 1;
	//status = buffer_append(buffer, ptr, size);
	if(buffer == NULL) 
		status = -1;
	else if(buffer->total_size - buffer->bytes_used < desired_length){
		int new_size = (buffer->total_size) * 2;
		char* tmp = (char*)malloc(sizeof(char) * new_size);
		if(tmp == NULL) {
			LOG_ERROR("Out of memory\n");
			return -1;
		}
		memcpy(tmp, buffer->contents, buffer->total_size);
		memset(buffer->contents, 0, buffer->total_size);
		free(buffer->contents);
		buffer->contents = tmp;
		buffer->total_size = new_size;
	} else {
		size_t bytes_copy = 0;
		for(int i = 0; i < size; i++) {
			if(ptr[i] == '\0') {
				break;
			}
			size_t pos = buffer->bytes_used + i;
			*(buffer->contents + pos) = ptr[i];
			bytes_copy++;
		}
		buffer->bytes_used += bytes_copy;
		*(buffer->contents + buffer->bytes_used) = '\0';
	}
	if(status != 0) {
		LOG_ERROR("Failed to write Buffer\n");
		return -1;
	}
	return size;
}

static size_t calc_replaced_url_len(const char* url) {
	size_t size = 0;
	size_t max = 0;
	size = strlen(url);
	for(size_t i = 0; i < size; i++) {
		if(url[i] != ' ') {
			max++;
			continue;
		}
		max += 3;
	}
	return max + 1;
}

static char* replace_url(const char* url) {
	size_t pos = 0;
	size_t size = 0;
	size_t max = 0;
	char* replaced_url = NULL;
	
	size = strlen(url);
	max = calc_replaced_url_len(url);
	replaced_url = calloc((size_t)1, max);
	if(replaced_url == NULL) {
		LOG_ERROR("calloc error\n");
		return NULL;
	}
	for(size_t i = 0; i < size; i++) {
		if(url[i] != ' ') {
			*(replaced_url + pos) = url[i];
			pos++;
			continue;
		}
		(void)strcat(replaced_url + pos, "%20");
		pos += 3;
	}
	return replaced_url;
}

static int http_get_header_common(const unsigned int flag, const char *key, const char *value,
                                  struct curl_slist **chunk)
{
    int nret = 0;
    size_t len = 0;
    char *header = NULL;
    const int extra_char_len = 3;

    if (flag == 0 || key == NULL || value == NULL) {
        return 0;
    }

    // format   key: value
    if (strlen(value) > (SIZE_MAX - strlen(key)) - extra_char_len) {
    	LOG_ERROR("Invalid authorization option");
        return -1;
    }

    // key + ": " + value + '\0'
    len = strlen(key) + strlen(value) + extra_char_len;
    header = calloc((size_t)1, len);
    if (header == NULL) {
    	LOG_ERROR("Out of memory");
        return -1;
    }

    nret = snprintf(header, len, "%s: %s", key, value);
    if (nret < 0 || (size_t)nret >= len) {
    	LOG_ERROR("Failed to print string");
    } else {
        *chunk = curl_slist_append(*chunk, header);
    }

    free(header);
    return nret == 0 ? 0 : -1;
}

static struct curl_slist *http_get_chunk_header(const struct http_get_options *options)
{
    int ret = 0;
    int i;
    struct curl_slist *chunk = NULL;
    char **custom_headers = NULL;

    ret = http_get_header_common(options->with_header_auth, "Authorization", options->authorization,
                                 &chunk);
    if (ret != 0) {
        goto out;
    }   

    if (options->with_header_json) {
        chunk = curl_slist_append(chunk, "Content-Type: application/json");
        // Disable "Expect: 100-continue"
        chunk = curl_slist_append(chunk, "Expect:");
    }   

    custom_headers = options->custom_headers;
    for (i = 0; custom_headers != NULL && custom_headers[i] != 0; i++) {
        chunk = curl_slist_append(chunk, custom_headers[i]);
    }   

    ret = http_get_header_common(options->with_header_accept, "Accept", options->accepts,
                                 &chunk);
    if (ret != 0) {
        goto out;
    }   

out:
    if (ret != 0) {
        curl_slist_free_all(chunk);
        chunk = NULL;
    }   

    return chunk;
}

static struct curl_slist* set_custom_header(CURL* curl_handle, const struct http_get_options* options) {
	struct curl_slist* chunk = NULL;
	chunk = http_get_chunk_header(options);
	if(chunk) {
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, chunk);
	}
	return chunk;
}

static void http_custom_general_options(CURL* curl_handle, const struct http_get_options* options) {
	if(options->timeout) {
		curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 30L);
		curl_easy_setopt(curl_handle, CURLOPT_LOW_SPEED_LIMIT, 1024L);
		curl_easy_setopt(curl_handle, CURLOPT_LOW_SPEED_TIME, 30L);
	}

	if(options->unix_socket_path) {
		curl_easy_setopt(curl_handle, CURLOPT_UNIX_SOCKET_PATH, options->unix_socket_path);
	}

	if(options->with_head) {
		curl_easy_setopt(curl_handle, CURLOPT_HEADER, 1L);
	}
	if(options->with_body == 0) {
		curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1L);
	}
	if(options->show_progress == 0) {
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	} else {
#if (LIBCURL_VERSION_NUM >= 0X072000)
		if(options->xferinfo && options->xferinfo_op) {
			curl_easy_setopt(curl_handle, CURLOPT_XFERINFOFUNCTION, options->xferinfo_op);
			curl_easy_setopt(curl_handle, CURLOPT_XFERINFODATA, options->xferinfo);
		}
#else
		if(options->progressinfo && options->progress_info_op) {
			curl_easy_setopt(curl_handle, CURLOPT_PROGRESSFUNCTION, options->progress_info_op);
			curl_easy_setopt(curl_handle, CURLOPT_PROGRESSDATA, options->progress_info);
		}
#endif
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 0L);
	}
	if(options->input) {
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, options->input);
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, options->input_len);
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
	}
	if(options->debug){
		curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
	}

}

static int http_custom_options(CURL* curl_handle, const struct http_get_options* options) {
	if(curl_handle == NULL)
		return -1;
	http_custom_general_options(curl_handle, options);
	//http_custom_ssl_options(curl_handle, options);
	return 0;
}

static int ensure_path_file(char** rpath, void* output, bool resume, FILE** pagefile, size_t* fsize) {
	const char* mode = "w+";
	unsigned int fdmode = 0;
	struct stat st;
	int f_fd;
	int fd;
	FILE* fp;
	char* path;
	char real_path[255] = {0};
	int err = -1;
	path = (char*)output;
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
	if(fd < 0 && errno != EEXIST) {
		LOG_ERROR("create file err!\n");
		goto err;
	}
	if(realpath(path, real_path) == NULL) {
		LOG_ERROR("get real path err!\n");
		goto err;
	}
	*rpath = strdup(real_path);
	if(resume) {
		mode = "a";
		if(stat(*rpath, &st) < 0) {
			LOG_ERROR("stat %s failed: %s", *rpath, strerror(errno));
			return -1;
		}
		*fsize = (size_t)st.st_size;
	} else {
		*fsize = 0;
	}
	if(strncmp(mode, "a", 1) == 0)
		fdmode = O_WRONLY | O_CREAT | O_APPEND;
	else if(strncmp(mode, "w+", 2) == 0) 
		fdmode = O_RDWR | O_TRUNC | O_CREAT;
	f_fd = open(*rpath, (int)fdmode, 0666);
	if(f_fd < 0) {
		LOG_ERROR("open file err!\n");
		goto err;
	}
	*pagefile = fdopen(f_fd, mode);
	if(*pagefile == NULL) {
		LOG_ERROR("fdopen err!\n");
		close(f_fd);
		goto err;
	}
	err = EXIT_SUCCESS;
err:
	return err;
}

static void check_buf_len(struct http_get_options *options, char *errbuf, CURLcode curl_result)
{
    int nret = 0;
    size_t len = 0;

    if (options == NULL || options->errmsg != NULL) {
        return;
    }   

    len = strlen(errbuf);
    if (len == 0) {
        nret = snprintf(errbuf, CURL_ERROR_SIZE, "curl response error code %d", curl_result);
        if (nret < 0 || (size_t)nret >= CURL_ERROR_SIZE) {
            //ERROR("Failed to print string for error buffer, errcode %d", curl_result);
            return;
        }
    }   
    //ERROR("curl response error code %d, error message: %s", curl_result, errbuf);
    free(options->errmsg);
    options->errmsg = strdup(errbuf);
    options->errcode = curl_result;

    return;
}

int http_request(const char* url, struct http_get_options* options, long* response_code, int recursive_len) {
	CURL* curl_handle = NULL;
	CURLcode curl_result = CURLE_OK;
	struct curl_slist* chunk = NULL;
	FILE* pagefile = NULL;
	char* rpath = NULL;
	int ret = 0;
	char errbuf[CURL_ERROR_SIZE] = { 0 };
	bool strbuf_args;
	bool file_args;
	char* redir_url = NULL;
	char* tmp = NULL;
	size_t fsize = 0;
	char* replaced_url = 0;

	curl_handle = curl_easy_init();
	if(curl_handle == NULL)
		return -1;
	replaced_url = replace_url(url);
	if(replaced_url == NULL) {
		ret = -1;
		goto out;
	}
	curl_easy_setopt(curl_handle, CURLOPT_URL, replaced_url);
	//curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);//recomended use in multi-thread environment 
	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errbuf);
	curl_easy_setopt(curl_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
#if (LIBCURL_VERSION_NUM >= 0x073600)
	curl_easy_setopt(curl_handle, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
#endif

#if (LIBCURL_VERSION_NUM >= 0x073400)
	curl_easy_setopt(curl_handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_MAX_TLSv1_3);
#endif

	ret = http_custom_options(curl_handle, options);
	if(ret) {
		goto out;
	}
	chunk = set_custom_header(curl_handle, options);
	strbuf_args = options->output && options->outputtype == HTTP_REQUEST_STRBUF;
    file_args = options->output && options->outputtype == HTTP_REQUEST_FILE;
	if(strbuf_args) {
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, options->output);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, fwrite_buffer);
	} else if(file_args) {
		if(ensure_path_file(&rpath, options->output, options->resume, &pagefile, &fsize) != 0) {
			ret = -1;
			goto out;
		}
		if(options->resume) {
			curl_easy_setopt(curl_handle, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)fsize);
		}
		curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, fwrite_file);
	} else {}
	curl_result = curl_easy_perform(curl_handle);
	if(curl_result != CURLE_OK) {
		LOG_ERROR("curl_result != CURLE_OK\n");
		check_buf_len(options, errbuf, curl_result);
		ret = -1;
	} else {
		if(response_code != NULL)
			curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, response_code);
		curl_easy_getinfo(curl_handle, CURLINFO_REDIRECT_URL, &tmp);
		if(tmp) {
			redir_url = strdup(tmp);
		}
	}
out:
	free(replaced_url);
	if(pagefile != NULL)
		fclose(pagefile);
	free(rpath);
	curl_easy_cleanup(curl_handle);
	curl_slist_free_all(chunk);
	if(redir_url) {
		if(options->output && options->outputtype == HTTP_REQUEST_STRBUF) {
			memset(((Buffer*)(options->output))->contents, 0, ((Buffer*)(options->output))->total_size);
			((Buffer*)(options->output))->bytes_used = 0;
		}
		if(options->with_header_auth && options->authorization) {
			options->with_header_auth = 0;
		}
		if(http_request(redir_url, options, response_code, recursive_len + 1)) {
			LOG_ERROR("Failed to get http request\n");
			ret = -1;
		}
		free(redir_url);
	}
	return ret;
}

static int on_message_begin(http_parser* p) {
	struct parsed_http_message* m = p->data;
	m->message_begin_cb_called = 1;
	return 0;
}

static int on_url(http_parser* parser, const char* buf, size_t len) {
	struct parsed_http_message* m = parser->data;
	strlncat(m->request_url, sizeof(m->request_url), buf, len);
	return 0;
}

static int on_status(http_parser* parser, const char* buf, size_t len) {
	struct parsed_http_message* m = parser->data;
	m->status_cb_called = 1;
	strlncat(m->response_status, sizeof(m->response_status), buf, len);
	return 0;
}

static int on_header_field(http_parser* parser, const char* buf, size_t len) {
	struct parsed_http_message* m= parser->data;
	if(m->last_header_element != FIELD) {
		if(m->num_headers + 1 >= MAX_HEADERS) {
			LOG_ERROR("too many headers exceeded\n");
			return -1;
		}
		m->num_headers++;
	}
	if(m->num_headers == 0) {
		LOG_ERROR("Failed to parse header\n");
		return -1;
	}
	strlncat(m->headers[m->num_headers-1][0], sizeof(m->headers[m->num_headers-1][0]), buf, len);
	m->last_header_element = FIELD;
	return 0;
}

static int on_header_value(http_parser* parser, const char* buf, size_t len) {
	struct parsed_http_message* m = parser->data;
	if(m->num_headers == 0) {
		LOG_ERROR("Failed to parse header value\n");
		return -1;
	}
	strlncat(m->headers[m->num_headers-1][1], sizeof(m->headers[m->num_headers-1][1]), buf, len);
	m->last_header_element = VALUE;
	return 0;
}

static int on_headers_complete(http_parser* parser) {
	struct parsed_http_message* m = parser->data;
	m->method = parser->method;
	m->status_code = (int)(parser->status_code);
	m->http_major = parser->http_major;
	m->http_minor = parser->http_minor;
	m->headers_complete_cb_called = 1;
	m->should_keep_alive = http_should_keep_alive(parser);
	return 0;
}

static int on_body(http_parser *parser, const char *buf, size_t len)
{
    struct parsed_http_message *m = parser->data;
    size_t newsize;
    char *body = NULL;
    if (m->body_size > (SIZE_MAX - len) - 1) {
    	LOG_ERROR("http body size is too large!");
        return -1;
    }
    newsize = m->body_size + len + 1;
    body = (char*)malloc(newsize);
    if (body == NULL) {
    	LOG_ERROR("Out of memory");
        return -1;
    }
    if (m->body != NULL && m->body_size > 0) {
        (void)memcpy(body, m->body, m->body_size);
        free(m->body);
    }
    m->body = body;
    strlncat(m->body, newsize, buf, len);
    m->body_size += len;
    //parser_check_body_is_final(parser);
    return 0;
}

static int on_message_complete(http_parser* parser) {
    struct parsed_http_message *m = parser->data;
    if (m->should_keep_alive != http_should_keep_alive(parser)) {
        fprintf(stderr, "\n\n *** Error http_should_keep_alive() should have same "
                "value in both on_message_complete and on_headers_complete "
                "but it doesn't! ***\n\n");
        abort();
    }   
    if (m->body_size &&
        http_body_is_final(parser) &&
        !m->body_is_final) {
        fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
                "on last on_body callback call "
                "but it doesn't! ***\n\n");
        abort();
    }   
    m->message_complete_cb_called = 1;
	m->body_is_final = http_body_is_final(parser);
    return 0;
}

static int on_chunk_header(http_parser* parser) {
	struct parsed_http_message* m = parser->data;
	int chunk_idx = m->num_chunks;
	m->num_chunks++;
	if(chunk_idx < MAX_CHUNKS && chunk_idx >= 0) {
		m->chunk_lengths[chunk_idx] = (int)(parser->content_length);
	}
	return 0;
}

static int on_chunk_complete(http_parser* parser) {
	struct parsed_http_message* m = parser->data;
	if(m->num_chunks != m->num_chunks_complete + 1) {
		LOG_ERROR("chunk_header_cb is not matched\n");
		return -1;
	}
	m->num_chunks_complete++;
	return 0;
}

static http_parser_settings g_settings = {
	.on_message_begin = on_message_begin,
	.on_url = on_url,
	.on_status = on_status,
	.on_header_field = on_header_field,
	.on_header_value = on_header_value,
	.on_headers_complete = on_headers_complete,
	.on_body = on_body,
	.on_message_complete = on_message_complete,
	.on_chunk_header = on_chunk_header,
	.on_chunk_complete = on_chunk_complete
};

static int parse_auth(pull_descriptor *desc, struct parsed_http_message *m) {
	int i = 0, j, len, end;
	int ret = 0;
	char* params, *schema, *auth;
	char* temp = NULL;
	challenge* c;
	for(i = 0; i < m->num_headers; i++) {
		if(!strcasecmp(m->headers[i][0], "www-authenticate")) {
			c = (challenge*)malloc(sizeof(challenge));
			auth = strdup(m->headers[i][1]);
			j = 0;
			while(*(auth + j) == ' ')
				j++;
			len = strlen(auth);
			while(len >= 1 && (auth[len-1] == '\n' || auth[len-1] == ' '))
				auth[--len] = '\0';
			params = strchr(auth + j, ' ');
			params[0] = 0;
			params += 1;
			schema = auth + j;
			temp = strtok(params, "=,");
			while(temp != NULL) {
				if(!strcmp(temp, "realm")) {
					temp = strtok(NULL, ",\0");
					c->realm = (char*)calloc(1, strlen(temp));
					strncpy(c->realm, temp + 1, strlen(temp) - 2);
				} else if(!strcmp(temp, "service")) {
					temp = strtok(NULL, ",\0");
					c->service = (char*)calloc(1, strlen(temp));
					strncpy(c->service, temp + 1, strlen(temp) - 2);
				}
				temp = strtok(NULL, "=,\0");
			}
			c->schema = (char*)calloc(1, strlen(schema) + 1);
			c->schema = strdup(schema);
			for(j = 0; j < CHALLENGE_MAX; j++) {
				if(desc->challenges[i].schema == NULL) {
					desc->challenges[i] = *c;
					break;
				}
			}
			if(j == CHALLENGE_MAX) {
				free(c);
			}
			free(auth);
		}
	}
out:
	return ret;
}

struct parsed_http_messsage;

static void free_parsed_http_message(struct parsed_http_message **message) {
	if(message == NULL || *message == NULL) {
		return;
	}

	free(((struct parsed_http_message*)(message))->body);
	((struct parsed_http_message*)(message))->body = NULL;
	free(*message);
	*message = NULL;
	return;
}

struct parsed_http_message* get_parsed_message(char* http_head) {
	int ret = 0, len;
	struct parsed_http_message* message = NULL;

	message = (struct parsed_http_message*)common_calloc_s(sizeof(struct parsed_http_message));
	if(message == NULL) {
		LOG_ERROR("Out of memory\n");
		ret = -1;
		goto out;
	}

	ret = parse_http_header(http_head, strlen(http_head), message);
	if(ret != 0) {
		LOG_ERROR("parse http header failed\n");
		ret = -1;
		goto out;
	}
out:
	if(ret != 0) {
		free_parsed_http_message(&message);
	}

	return message;
}

char* get_header_value(const struct parsed_http_message* m, const char* header) {
	int i = 0;
	char* ret = NULL;
	if(m == NULL || header == NULL) {
		LOG_ERROR("Empty arguments\n");
		return NULL;
	}
	for(i = 0; i < m->num_headers; i++) {
		if(strcasecmp(m->headers[i][0], header) == 0) {
			ret = (char*)m->headers[i][1];
			break;
		}
	}
	return ret;
}

int parse_ping_header(pull_descriptor* desc, char* http_head) {
	char* version;
	http_parser* parser;
	int ret = 0, len;
	struct parsed_http_message* message;
	version = NULL;
	message = get_parsed_message(http_head);
	if(message == NULL) {
		ret = -1;
		goto out;
	}
	if(message->status_code != status_unauthorized && message->status_code != status_ok) {
		LOG_ERROR("registry response invalid status code %d", message->status_code);
		ret = -1;
		goto out;
	}
	version = get_header_value(message, "Docker-Distribution-Api-Version");
	if(version == NULL || strcasecmp(version, "registry/2.0")) {
		LOG_ERROR("version %s not supported", version);
		ret = -1;
		goto out;	
	}
	ret = parse_auth(desc, message);
	if(ret != 0) {
		LOG_ERROR("Parse www-authenticate header failed\n");
		goto out;
	}
out:
	free(message->body);
	message->body = NULL;
	free(message);
	message = NULL;
	return ret;
}

int parse_http_header(const char *http_head, int head_len, struct parsed_http_message *message) {
	int ret = 0;
	size_t nparsed = 0;
	char *real_message, *body;
	http_parser *parser;
	real_message = body = NULL;

	real_message = strstr(http_head, "HTTP/1.1");
	if(real_message == NULL) {
		LOG_ERROR("Failed to parse response, the response do not have HTTP/1.1\n");
		ret = -1;
		goto out;
	}

	body = strstr(real_message, BODY_DELIMITER);
	if(body != NULL) {
		*(body + strlen(BODY_DELIMITER)) = 0;
	}

	parser = (http_parser*)malloc(sizeof(http_parser));
	parser->data = message;
	http_parser_init(parser, HTTP_RESPONSE);
	int len = strlen(real_message);
	nparsed = http_parser_execute(parser, &g_settings, real_message, len);
	if(nparsed != len) {
		LOG_ERROR("Failed to parse it, parsed : %d, input : %d\n", ret, len);
		ret = -1;
		goto free_out;
	}
free_out:
	free(parser);
out:
	return ret;
}

static int http_request_token(pull_descriptor *desc, challenge *c, char **output) {
	char* url, *auth_header;
	int ret, url_len;
	Buffer* output_buffer = NULL;
	struct http_get_options* options;
	options = calloc_s(1, sizeof(struct http_get_options));
	output_buffer = buffer_alloc(HTTP_GET_BUFFER_SIZE);
	options->with_body = 1;
	options->with_head = 0;
	options->outputtype = HTTP_REQUEST_STRBUF;
	options->output = output_buffer;
	options->timeout = true;
	url_len = 0;
	url_len += strlen(c->realm) + strlen("?");
	if(desc->username != NULL) {
		url_len += strlen("account=") + strlen(desc->username) + strlen("&");
	}
	if(c->service != NULL) {
		url_len += strlen("service=") + strlen(c->service) + strlen("&");
	}
	if(desc->scope != NULL) {
		url_len += strlen("scope=") + strlen(desc->scope) +strlen("&"); 
	}
	url = calloc_s(1, url_len);
	strcat(url, c->realm);
	if(desc->username != NULL || c->service != NULL || desc->scope != NULL)
		strcat(url, "?");
	if(desc->username != NULL) {
		strcat(url, "account=");
		strcat(url, desc->username);
		if(c->service != NULL || desc->scope != NULL) 
			strcat(url, "&");
	}
	if(c->service != NULL) {
		strcat(url, "service=");
		strcat(url, c->service);
		if(desc->scope != NULL) {
			strcat(url, "&");
		}
	}
	if(desc->scope != NULL) {
		strcat(url, "scope=");
		strcat(url, desc->scope);
	}

	ret = http_request(url, options, NULL, 0);
	if(ret) {
		LOG_ERROR("Failed to get http request: %s\n", options->errmsg);
		ret = -1;
		goto out;
	}
	*output = strdup_s(((Buffer*)(options->output))->contents);
out:
	free_http_get_options(options);
	buffer_free(output_buffer);
	free(url);
	return ret;
} 

static char *auth_header_str(const char *schema, const char *value)
{
    int ret = 0;
    int sret = 0;
    char *auth_header = NULL;
    size_t auth_header_len = 0;

    if (schema == NULL || value == NULL) {
    	LOG_ERROR("Invalid NULL pointer");
        return NULL;
    }   

    // Auth header's format example:
    // Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l
    auth_header_len = strlen("Authorization") + strlen(": ") + strlen(schema) + strlen(" ") + strlen(value) + 1;
    auth_header = calloc_s(1, auth_header_len);
    if (auth_header == NULL) {
    	LOG_ERROR("out of memory");
        ret = -1; 
        goto out;
    }   

    sret = snprintf(auth_header, auth_header_len, "Authorization: %s %s", schema, value);
    if (sret < 0 || (size_t)sret >= auth_header_len) {
        ret = -1; 
    	LOG_ERROR("Failed to sprintf authorization");
        goto out;
    }   

out:
    if (ret != 0) {
        free(auth_header);
        auth_header = NULL;
    }   

    return auth_header;
}

static int get_bearer_token(pull_descriptor* desc, struct http_get_options* options) {
	int i, ret;
	char* err;
	i = ret = 0;
	for(i = 0; i < CHALLENGE_MAX; i++) {
		if(desc->challenges[i].schema == NULL || desc->challenges[i].realm == NULL)
			continue;
		if(!strcasecmp(desc->challenges[i].schema, "Basic")) {

		} else if(!strcasecmp(desc->challenges[i].schema, "Bearer")) {
			challenge* c = &desc->challenges[i];
			char* output;
			char* auth_header = NULL;
			//free(c->cached_token);
			c->cached_token = NULL;
			c->expires_time = 0;
			ret = http_request_token(desc, c, &output);
			if(ret != 0 || output == NULL) {
				LOG_ERROR("get token err!\n");
				ret = -1;
				goto out;
			}
			registry_token* token = registry_token_parse_data(output, NULL, &err);
			if(token == NULL) {
				ret = -1;
				LOG_ERROR("parse token from response failed!\n");
				goto out;
			}	
			if(token->token != NULL) {
				c->cached_token = strdup_s(token->token);
			} else {
				ret = -1;
				LOG_ERROR("no valid token found!\n");
				goto out;
			}
			if(token->expires_in > MIN_TOKEN_EXPIRES_IN) {
				c->expires_time = time(NULL) + token->expires_in;
			} else {
				c->expires_time = MIN_TOKEN_EXPIRES_IN;
			}
			auth_header = auth_header_str("Bearer", desc->challenges[i].cached_token);
			if(auth_header == NULL) {
				goto out;
			}
			ret = array_append(&options->custom_headers, (const char*)auth_header);
			if(ret != 0) {
				LOG_ERROR("append custom headers failed\n");
				ret = -1;
				goto out;
			}
			free(auth_header);
		}
	}	
out:
	return ret;
}

static int xfer(void *p, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
{
    bool *cancel = p;
    if (*cancel) {
        // return nonzero code means abort transition
        return -1; 
    }   
    return 0;
}

int http_request_buf(pull_descriptor* desc, const char* url, const char** custom_headers, char** output, resp_data_type type) {
	int ret = 0;
	struct http_get_options* options = NULL;
	Buffer* output_buffer = NULL;
	if(desc == NULL || url == NULL || output == NULL) {
		LOG_ERROR("Invalid NULL pointer\n");
		return -1;
	}
	options = (struct http_get_options *)calloc_s(1, sizeof(struct http_get_options));
	output_buffer = buffer_alloc(HTTP_GET_BUFFER_SIZE);
	if(options == NULL) {
		LOG_ERROR("Failed to malloc http_get_options\n");
		ret = -1;
		goto out;
	}
	if(output_buffer == NULL) {
		LOG_ERROR("Failed to malloc output_buffer\n");
		ret = -1;
		goto out;	
	}
	if(type == BODY_ONLY || type == HEAD_BODY) {
		options->with_head = 1;
	}
	if(type == HEAD_ONLY || type == HEAD_BODY) {
		options->with_head = 1;
	}
	if(custom_headers != NULL) {
		options->custom_headers = str_array_dup(custom_headers, array_len(custom_headers));
		if(options->custom_headers == NULL) {
			LOG_ERROR("dup headers failed\n");
			ret = -1;
			goto out;
		}
	}
	ret = get_bearer_token(desc, options);
	options->outputtype = HTTP_REQUEST_STRBUF;
	options->output = output_buffer;
	options->timeout = true;
	ret = http_request(url, options, NULL, 0);
	if(ret) {
		LOG_ERROR("Failed to get http request: %s\n", options->errmsg);
		ret = -1;
		goto out;
	}
	*output = strdup_s(output_buffer->contents);
out:
	buffer_free(output_buffer);
	free_http_get_options(options);
	return ret;
}

int http_request_file(pull_descriptor* desc, const char* url, const char** custom_headers, char* file, resp_data_type type) {
	int ret = 0;
	struct http_get_options* options = NULL;
	options = calloc_s(1, sizeof(struct http_get_options));
	if(type == HEAD_BODY) {
		options->with_head = 1;
	}
	options->with_body = 1;
	if(type == RESUME_BODY) {
		options->resume = true;
	}
	options->outputtype = HTTP_REQUEST_FILE;
	options->output = file;
	options->show_progress = 1;
	options->progressinfo = &desc->cancel;
	//options->progress_info_op = progress;
	options->xferinfo = &desc->cancel;
	options->xferinfo_op = xfer;
	options->timeout = true;
	if(custom_headers != NULL) {
		options->custom_headers = str_array_dup(custom_headers, array_len(custom_headers));
		if(options->custom_headers == NULL) {
			LOG_ERROR("dup headers failed\n");
			ret = -1;
			goto out;		
		}
	}
	ret = get_bearer_token(desc, options);
	ret = http_request(url, options, NULL, 0);
	if(ret != 0) {
		LOG_ERROR("Failed to get http request: %s\n", options->errmsg);
		ret = -1;
	}
out:
	free_http_get_options(options);
	return ret;
}

void free_http_get_options(struct http_get_options *options)
{
    if (options == NULL) {
        return;
    }
    free(options->accepts);
    options->accepts = NULL;

    free(options->authorization);
    options->authorization = NULL;

    free(options->unix_socket_path);
    options->unix_socket_path = NULL;

    free(options->custom_headers);
    options->custom_headers = NULL;

    free(options->ca_file);
    options->ca_file = NULL;

    free(options->cert_file);
    options->cert_file = NULL;

    free(options->key_file);
    options->key_file = NULL;

    free(options->errmsg);
    options->errmsg = NULL;

    /* The options->output is a FILE pointer, we should not free it here */
    free(options);
    return;
}
