#include <ctype.h>
#include <sys/utsname.h>

#include "http.h"
#include "registry.h"
#include "sha256.h"
#include "config.h"
#include "configs_constants.h"
#include "storage.h"
#include "time.h"


#define MANIFEST_BIG_DATA_KEY "manifest"
#define MAX_CONCURRENT_DOWNLOAD_NUM 5
#define DEFAULT_WAIT_TIMEOUT 15

int split_image_name(const char* image_name, char** host, char** name, char** tag_digest) {
	char* tag_digest_pos = NULL;
	char* name_pos = NULL;
	char* tmp_image_name = NULL;
	tmp_image_name = strdup_s(image_name);
	tag_digest_pos = strchr(tmp_image_name, '@');
	if(tag_digest_pos == NULL) {
		tag_digest_pos = strchr(tmp_image_name, ':');
		if(strchr(tag_digest_pos, '/') != NULL)
			tag_digest_pos = NULL;
	}
	if(tag_digest_pos != NULL) {
		*tag_digest_pos = '\0';
		tag_digest_pos++;
		if(tag_digest != NULL) {
			*tag_digest = strdup_s(tag_digest_pos);
		}
	}
	name_pos = strchr(tmp_image_name, '/');
	if(name_pos != NULL) {
		*(name_pos) = '\0';
		name_pos++;
		if(name != NULL) {
			*name = strdup_s(name_pos);
		}
		if(host != NULL) {
			*host = strdup_s(tmp_image_name);
		}
	}
	free(tmp_image_name);
	tmp_image_name = NULL;
	return 0;
}

extern configs_constants *get_constants();

static void update_host(pull_descriptor *desc) {
    size_t i = 0; 
    configs_constants *config = get_constants();
	if(config == NULL) {
		printf("NULL\n");
		return;
	}
    json_map_string_string *registry_transformation = NULL;
    if (desc == NULL || config == NULL) {
        printf("Invalid NULL param\n");
        return;
    }    
    registry_transformation = config->registry_transformation;
    if (registry_transformation == NULL) {
        return;
    } 
    // replace specific registry to another due to compatability reason
    for (i = 0; i < registry_transformation->len; i++) {
        if (registry_transformation->keys[i] == NULL || registry_transformation->values[i] == NULL) {
            continue;
        }
        if (strcmp(desc->host, registry_transformation->keys[i]) == 0) { 
            free(desc->host);
            desc->host = strdup_s(registry_transformation->values[i]);
            break;
        }
    }    
    return;
}

static int prepare_pull_desc(pull_descriptor *desc, registry_pull_options *options) {
	int ret = 0;
	int sret = 0;
	char blobpath[PATH_MAX] = {0};
	char scope[PATH_MAX] = {0};
	char image_tmp_path[PATH_MAX] = {0};
	if(desc == NULL || options == NULL) {
		printf("Invalid NULL param\n");
		return -1;
	}
	ret = split_image_name(options->image_name, &desc->host, &desc->name, &desc->tag);
	if(ret != 0) {
		printf("split image name %s err\n", options->image_name);
		ret = -1;
		goto out;
	}
	if(desc->host == NULL || desc->name == NULL || desc->tag == NULL) {
		printf("Invalid image %s, host or name or tag not found\n", options->image_name);
		ret = -1;
		goto out;
	}
	update_host(desc);
	sret = snprintf(image_tmp_path, PATH_MAX, "%s/tmpdir", _root_dir);
	sret = snprintf(blobpath, PATH_MAX, "%s/registry-XXXXXX", image_tmp_path);
	ret = mkdir_p(image_tmp_path, 0700);
	if(ret < 0) {
		printf("Failed to create image directory %s.\n", image_tmp_path);
		return -1;
	}
	if(mkdtemp(blobpath) == NULL) {
		printf("make temporary directory %s failed: %s\n", blobpath, strerror(errno));
		ret = -1;
		goto out;
	}
	sret = snprintf(scope, sizeof(scope), "repository:%s:pull", desc->name);
	if(sret < 0 || (size_t)sret >= sizeof(scope)) {
		printf("Failed to sprintf scope\n");
		ret = -1;
		goto out;
	}
	desc->cond_inited = true;
	desc->image_name = strdup_s(options->image_name);
	desc->dest_image_name = strdup_s(options->dest_image_name);
	desc->scope = strdup_s(scope);
	desc->cancel = false;
	desc->rollback_layers_on_failure = true;
	desc->blobpath = strdup_s(blobpath);
	if (options->auth.username != NULL && options->auth.password != NULL) {
        desc->username = strdup_s(options->auth.username);
        desc->password = strdup_s(options->auth.password);
    } else {
		desc->username = NULL;
		desc->password = NULL;
    }
out:
	return ret;
}

static int append_manifests_accepts(char*** custom_headers) {
    int i = 0; 
    int ret = 0; 
    int sret = 0; 
    char accept[MAX_ACCEPT_LEN] = { 0 }; 
    const char *mediatypes[] = { DOCKER_MANIFEST_SCHEMA2_JSON,
                                 DOCKER_MANIFEST_SCHEMA1_PRETTYJWS,
                                 DOCKER_MANIFEST_SCHEMA1_JSON,
                                 DOCKER_MANIFEST_SCHEMA2_LIST,
                                 MEDIA_TYPE_APPLICATION_JSON,
                                 OCI_MANIFEST_V1_JSON,
                                 OCI_INDEX_V1_JSON
                               };

    for (i = 0; i < sizeof(mediatypes) / sizeof(mediatypes[0]); i++) {
        sret = snprintf(accept, MAX_ACCEPT_LEN, "Accept: %s", mediatypes[i]);
        if (sret < 0 || (size_t)sret >= MAX_ACCEPT_LEN) {
            printf("Failed to sprintf accept media type %s", mediatypes[i]);
            ret = -1;
            goto out; 
        }
        ret = array_append(custom_headers, accept);
        if (ret != 0) { 
            printf("append accepts failed");
            goto out; 
        }
    }    

out:
    return ret; 
}

int registry_ping(pull_descriptor* desc) {
	int ret = 0;
	int sret = 0;
	char* output = NULL;
	char url[1024] = { 0 };
	char** headers = NULL;
	if(desc == NULL) {
		printf("Invalid NULL param\n");
		return -1;
	}
	if(desc->protocol != NULL) {
		return 0;
	}
	sret = snprintf(url, sizeof(url), "%s://%s/v2/", "https", desc->host);
	if(sret < 0 || sret >= sizeof(url)) {
		printf("Failed to sprintf url for ping, host is %s\n", desc->host);
		ret = -1;
		goto out;
	}
	ret = array_append(&headers, DOCKER_API_VERSION_HEADER);
	if(ret != 0) {
		printf("append api version to header failed\n");
		ret = -1;
		goto out;
	}
	ret = http_request_buf(desc, url, (const char**)headers, &output, HEAD_BODY);
	if(ret != 0) {
		printf("http request failed\n");
		goto out;
	}
	ret = parse_ping_header(desc, output);
	if(ret != 0) {
		printf("parse ping header failed, response: %s\n", output);
		goto out;
	}
	desc->protocol = strdup_s("https");
out:
	free(output);
	free(headers);
	return ret;
}

static int registry_request(pull_descriptor* desc, char* path, char** custom_headers, char* file, char** output_buffer, resp_data_type type, CURLcode* errcode){
	int ret = 0;
	int sret = 0;
	char url[PATH_MAX] = { 0 };
	char** headers = NULL;
	if(desc == NULL || path == NULL || (file == NULL && output_buffer == NULL)) {
		printf("invalid NULL pointer\n");
		return -1;
	}
	ret = registry_ping(desc);
	if(ret != 0) {
		printf("ping failed\n");
		return -1;
	}
	sret = snprintf(url, sizeof(url), "%s://%s%s", desc->protocol, desc->host, path);
	if(sret < 0 || sret >= sizeof(url)) {
		printf("Failed to sprintf url, path is %s\n", path);
		ret = -1;
		goto out;
	}
	headers = str_array_dup((const char **)custom_headers, array_len((const char **)custom_headers));
	if(ret != 0) {
		printf("duplicate custom headers failed\n");
		ret = -1;
		goto out;
	}
	ret = array_append(&headers, DOCKER_API_VERSION_HEADER);
	if(ret != 0) {
		printf("append api version to header failed\n");
		ret = -1;
		goto out;
	}
	if(output_buffer != NULL) {
		ret = http_request_buf(desc, url, (const char**)headers, output_buffer, type);
		if(ret != 0) {
			printf("http request buffer failed, url: %s\n", url);
			goto out;
		}
	} else {
		ret = http_request_file(desc, url, (const char**)headers, file, type);
		if(ret != 0) {
			printf("http request buffer failed, url: %s\n", url);
			goto out;
		}
	}
out:
	free(headers);
	return ret;
}

static int split_head_body(char* file, char** http_head) {
	int ret = 0;
	char* all = NULL;
	char* head = NULL;
	char* deli = "\r\n\r\n";
	char* body = NULL;
	
	all = read_text_file(file);
	if(all == NULL) {
		printf("read file %s failed\n", file);
		return -1;
	}
	head = strstr(all, "HTTP/1.1");
	if(head == NULL) {
		printf("No Http/1.1 found\n");
		ret = -1;
		goto out;
	}
	body = strstr(head, deli);
	if(body == NULL) {
		deli = "\n\n";
		body = strstr(head, deli);
		if(body == NULL) {
			printf("No body found, data=%s\n", head);
			ret = -1;
			goto out;
		}
	}
	body += strlen(deli);
	ret = write_file(file, body, strlen(body), 0600);
	if(ret != 0) {
		printf("rewrite body to file failed\n");
		ret = -1;
		goto out;
	}
	*body = 0;
	*http_head = strdup_s(head);
out:
	free(all);
	all = NULL;
	return ret;
}

static int parse_manifest_head(char* http_head, char** content_type, char** digest) {
	int ret = 0;
	struct parsed_http_message* message = NULL;
	char* value = NULL;
	if(http_head == NULL || content_type == NULL || digest == NULL) {
		printf("invalid NULL pointer\n");
		return -1;
	}
	message = get_parsed_message(http_head);
	if(message == NULL) {
		ret = -1;
		goto out;
	}
	if(message->status_code != status_ok) {
		printf("registry response invalid status code %d\nresponse:%s\n", message->status_code, http_head);
		ret = -1;
		goto out;
	}
	value = get_header_value(message, "Content-Type");
	if(value == NULL) {
		printf("Get content type from message header failed, response: %s", http_head);
		ret = -1;
		goto out;
	}
	*content_type = strdup_s(value);
	value = get_header_value(message, "Docker-Content-Digest");
	if(value != NULL) {
		*digest = strdup_s(value);
	}
out:
	if(ret != 0) {
		free(*content_type);
		*content_type = NULL;
		free(*digest);
		*digest = NULL;
	}
	free(message);
	return ret; 
}

static int fetch_manifest_list(pull_descriptor *desc, char *file, char **content_type, char **digest)
{
    int ret = 0;
    int sret = 0;
    char *http_head = NULL;
    char **custom_headers = NULL;
    char path[PATH_MAX] = { 0 };
    CURLcode errcode = CURLE_OK;
    int retry_times = 5;

    if (desc == NULL || content_type == NULL || digest == NULL) {
        printf("Invalid NULL pointer\n");
        return -1;
    }

    ret = append_manifests_accepts(&custom_headers);
    if (ret != 0) {
        printf("append accepts failed\n");
        goto out;
    }

    sret = snprintf(path, sizeof(path), "/v2/%s/manifests/%s", desc->name, desc->tag);
    if (sret < 0 || (size_t)sret >= sizeof(path)) {
        printf("Failed to sprintf path for manifest\n");
        ret = -1;
        goto out;
    }

    while (retry_times > 0) {
        retry_times--;
        ret = registry_request(desc, path, custom_headers, file, NULL, HEAD_BODY, &errcode);
        if (ret != 0) {
            if (retry_times > 0 && !desc->cancel) {
                continue;
            }
            printf("registry: Get %s failed\n", path);
            goto out;
        }
        break;
    }

   	ret = split_head_body(file, &http_head);
	if(ret != 0) {
		printf("registry: Split %s to head body failed\n", file);
		return -1;
	}

	ret = parse_manifest_head(http_head, content_type, digest);
	if(ret != 0) {
		ret = -1;
		goto out;
	}
out:
	free(http_head);
	free_array(custom_headers);
	return ret;
}

static char *get_cpu_variant()
{
    char *variant = NULL;
    char cpuinfo[1024] = { 0 }; 
    char *start_pos = NULL;
    char *end_pos = NULL;
	int fd = open("/proc/cpuinfo", O_RDONLY, 0);
	if(fd == -1) {
		printf("open /proc/cpuinfo err!\n");
		return NULL;
	}
	int num_read = read(fd, &cpuinfo, sizeof(cpuinfo) - 1);
	if(num_read > 0) {
		cpuinfo[num_read] = 0;
	}
	close(fd);
    start_pos = strstr(cpuinfo, "CPU architecture");
    if (start_pos == NULL) {
        printf("can not found the key \"CPU architecture\" when try to get cpu variant\n");
        return NULL;
    } 
    end_pos = strchr(start_pos, '\n');
    if (end_pos != NULL) {
        *end_pos = 0; 
    }    
    start_pos = strchr(start_pos, ':');
    if (start_pos == NULL) {
        printf("can not found delimiter \":\" when try to get cpu variant\n");
        return NULL;
    }    
    start_pos += 1;    // skip char ":"
    //util_trim_newline(start_pos);
	int len = strlen(start_pos);
	while(len >= 1 && start_pos[len-1] == '\n')
		start_pos[--len] = '\0';
	while(isspace(*start_pos))
		start_pos++;
	len = strlen(start_pos);
	while(isspace(*(start_pos + len - 1))) {
		*(start_pos + len - 1) = '\0';
		len--;
	}
    //start_pos = util_trim_space(start_pos);

    variant = start_pos;
	for(char* pos = variant; *pos; pos++) {
		*pos = (char)tolower((int)(*pos));
	}

    return variant;
}

static int select_docker_manifest(registry_manifest_list* manifests, char** content_type, char** digest) {
	size_t i = 0;
	int ret = 0;
	char* host_os = NULL;
	char* host_arch = NULL;
	char* host_variant = NULL;
	registry_manifest_list_manifests_platform* platform = NULL;
	bool found = false;
	struct utsname uts;
	if(manifests == NULL || content_type == NULL || digest == NULL) {
		printf("Invalid NULL pointer\n");
		return -1;
	}
	if(uname(&uts) < 0) {
		printf("Failed to read host arch and os: %s\n", strerror(errno));
		return -1;
	}
	host_os = strdup_s(uts.sysname);
	host_arch = strdup_s("amd64");
	host_variant = get_cpu_variant();
	for(char* pos = host_os; *pos; pos++) {
		*pos = (char)tolower((int)(*pos));
	}
	for(i = 0; i < manifests->manifests_len; i++) {
		platform = manifests->manifests[i]->platform;
		if(platform == NULL || platform->architecture == NULL || platform->os == NULL)
			continue;
		if(!strcasecmp(platform->architecture, host_arch) && !strcasecmp(platform->os, host_os) && ( host_variant == NULL || !strcasecmp(host_variant, platform->variant))) {
			//free(*content_type);
			*content_type = strdup_s(manifests->manifests[i]->media_type);
			//free(*digest);
			*digest = strdup_s(manifests->manifests[i]->digest);
			found = true;
			goto out;
		}
	}
	ret = -1;
	printf("Cann't match any manifest, host os %s, host arch %s\n", host_os, host_arch);
out:
	free(host_os);
	free(host_arch);
	if(host_variant != NULL)
		free(host_variant);
	if(found && (*digest == NULL || *content_type == NULL)) {
		printf("Matched manifest have NULL digest or mediatype in manifest\n");
		ret = -1;
	}
	return ret;
}

static int select_oci_manifest(oci_image_index *index, char **content_type, char **digest) {
	size_t i = 0;
	int ret = 0;
	char *host_os = NULL;
	char *host_arch = NULL;
	char *host_variant = NULL;
	oci_image_index_manifests_platform *platform = NULL;
	bool found = false;
	struct utsname uts;

	if(index == NULL || content_type == NULL || digest == NULL) {
		printf("Invalid NULL pointer\n");
		return -1;
	}
	if(uname(&uts) < 0) {
		printf("Failed to read host arch and os: %s\n", strerror(errno));
		return -1;
	}
	host_os = strdup_s(uts.sysname);
	host_arch = strdup_s("amd64");
	host_variant = get_cpu_variant();
	for(char* pos = host_os; *pos; pos++) {
		*pos = (char)tolower((int)(*pos));
	}

	for(i = 0; i < index->manifests_len; i++) {
		platform = index->manifests[i]->platform;
		if(platform == NULL || platform->architecture == NULL || platform->os == NULL) {
			continue;
		}
		if(!strcasecmp(platform->architecture, host_arch) && !strcasecmp(platform->os, host_os) && ( host_variant == NULL || !strcasecmp(host_variant, platform->variant))) {
			free(*content_type);
			*content_type = strdup_s(index->manifests[i]->media_type);
			free(*digest);
			*digest = strdup_s(index->manifests[i]->digest);
			found = true;
			goto out;
		}
	}

	ret = -1;
	printf("Cann't match any manifest, host os %s, host arch %s, host variant %s\n", host_os, host_arch, host_variant);
out:
	free(host_os);
	host_os = NULL;
	free(host_arch);
	host_arch = NULL;
	free(host_variant);
	host_variant = NULL;

	if(found && (*digest == NULL || *content_type == NULL)) {
		printf("Matched manifest gave NULL digest or mediatype in manifest\n");
		ret = -1;
	}
	return ret;
}

static int select_manifest(char* file, char** content_type, char** digest) {
	int ret = 0;
	registry_manifest_list* manifests = NULL;
	oci_image_index *index = NULL;
	char* err = NULL;
	if(file == NULL || content_type == NULL || *content_type == NULL || digest == NULL) {
		printf("Invalid NULL pointer\n");
		return -1;
	}
	if(!strcmp(*content_type, OCI_INDEX_V1_JSON)) {
		index = oci_image_index_parse_file((const char*)file, NULL, &err);
		if(index == NULL) {
			printf("parse oci image index failed : %s\n", err);
			ret = -1;
			goto out;
		}
		ret = select_oci_manifest(index, content_type, digest);
		if(ret != 0) {
			printf("select manifest failed\n");
			ret = -1;
			goto out;
		}
	}
	else if(!strcmp(*content_type, DOCKER_MANIFEST_SCHEMA2_LIST)) {
		manifests = registry_manifest_list_parse_file((const char*)file, NULL, &err);
		if(manifests == NULL) {
			printf("parse docker image manifest list failed\n");
			ret = -1;
			goto out;
		}
		ret = select_docker_manifest(manifests, content_type, digest);
		if(ret != 0) {
			printf("select docker manifest failed\n");
			ret = -1;
			goto out;
		}
	} else {
		printf("Unexpected content type %s\n", *content_type);
		ret = -1;
		goto out;
	}
out:
	if(manifests != NULL) {
		free(manifests);
	}
	free(err);
	return ret;
}

static int fetch_data(pull_descriptor *desc, char *path, char *file, char *content_type, char *digest) {
	int ret = 0; 	
	int sret = 0;
	char accept[MAX_ELEMENT_SIZE] = { 0 };
	char** custom_headers = NULL;
	int retry_times = RETRY_TIMES;
	resp_data_type type = BODY_ONLY;
	bool forbid_resume = false;
	if(desc == NULL || path == NULL || file == NULL || content_type == NULL) {
		printf("Invalid NULL pointer\n");
		return -1;
	}
	sret = snprintf(accept, MAX_ACCEPT_LEN, "Accept: %s", content_type);
	if(sret < 0 || sret >= MAX_ACCEPT_LEN) {
		printf("Failed to sprintf accept media type %s\n", content_type);
		ret = -1;
		goto out;
	}
	ret = array_append(&custom_headers, accept);
	if(ret != 0) {
		printf("append accepts failed\n");
		goto out;
	}
	while(retry_times > 0) {
		retry_times--;
		ret = registry_request(desc, path, custom_headers, file, NULL, type, NULL);
		if(ret != 0) {
			printf("Get %s failed\n", path);
			desc->cancel = true;
			goto out;
		}
		if(strcmp(content_type, DOCKER_MANIFEST_SCHEMA1_PRETTYJWS) && digest != NULL) {
			//if(!sha256_valid_digest_file(file, digest)) {
			//	printf("data from %s does not have digest %s", path, digest);
			//	desc->cancel = true;
			//	goto out;
			//}
		}
		break;
	}
out:
	free(custom_headers);
	return ret;
}

static int fetch_manifest_data(pull_descriptor* desc, char* file, char** content_type, char** digest) {
	int ret = 0;
	int sret = 0;
	char path[1024] = { 0 };
	char* manifest_text = NULL;
	if(desc == NULL || file == NULL || content_type == NULL || *content_type == NULL || digest == NULL) {
		printf("Invalid NULL pointer\n");
		return -1;
	}
	if(!strcmp(*content_type, DOCKER_MANIFEST_SCHEMA2_LIST) || !strcmp(*content_type, OCI_INDEX_V1_JSON)) {
		ret = select_manifest(file, content_type, digest);
		if(ret != 0) {
			manifest_text = read_text_file(file);
			printf("select manifest failed, manifest:%s\n", manifest_text);
			free(manifest_text);
			manifest_text = NULL;
			goto out;
		}
		sret = snprintf(path, sizeof(path), "/v2/%s/manifests/%s", desc->name, *digest);
		if(sret < 0 || sret >= sizeof(path)) {
			printf("Failed to sprintf path for manifest\n");
			ret = -1;
			goto out;
		}
		ret = fetch_data(desc, path, file, *content_type, *digest);
		if(ret != 0) {
			printf("registry: Get %s failed, path\n", path);
			goto out;
		}
	}
out:
	return ret;
}

static int fetch_manifest(pull_descriptor *desc) {
	int ret = 0;
	int sret = 0;
	char file[PATH_MAX] = { 0 };
	char *content_type = NULL;
	char *digest = NULL;

	if(desc == NULL) {
		printf("Invalid NULL pointer\n");
		return -1;
	}

	sret = snprintf(file, sizeof(file), "%s/manifest", desc->blobpath);
	if(sret < 0 || (size_t)sret >= sizeof(file)) {
		printf("Failed to sprintf file for manifest\n");
		return -1;
	}

    ret = fetch_manifest_list(desc, file, &content_type, &digest);
    if (ret != 0) { 
        ret = -1;
        goto out; 
    }

	ret = fetch_manifest_data(desc, file, &content_type, &digest);
	if(ret != 0) {
		printf("fetch manifest data err!\n");
		return -1;
	}
	desc->manifest.media_type = strdup_s(content_type);
	desc->manifest.digest = strdup_s(digest);
	desc->manifest.file = strdup_s(file);
out:
	free(content_type);
	free(digest);
	return ret;
}

static int parse_manifest_schema2(pull_descriptor* desc) {
	registry_manifest_schema2* manifest;
	int ret = 0;
	size_t i = 0;
	parser_error err;
	manifest = registry_manifest_schema2_parse_file(desc->manifest.file, NULL, &err);
	if(manifest == NULL) {
		printf("parse manifest schema2 failed\n");
		ret = -1;
		goto out;
	}
	desc->config.media_type = strdup_s(manifest->config->media_type);
	desc->config.digest = strdup_s(manifest->config->digest);
	desc->config.size = manifest->config->size;
	desc->layers = calloc_s(sizeof(layer_blob), manifest->layers_len);
	if(desc->layers == NULL) {
		printf("out of memory\n");
		ret = -1;
		goto out;
	}
	for(i = 0; i < manifest->layers_len; i++) {
		if(strcmp(manifest->layers[i]->media_type, DOCKER_IMAGE_LAYER_TAR_GZIP) &&
		   strcmp(manifest->layers[i]->media_type, DOCKER_IMAGE_LAYER_FOREIGN_TAR_GZIP)) {
			printf("Unsupported layer's media type %s, layer index %zu", manifest->layers[i]->media_type, i);
			ret = -1;
			goto out;
		}
		desc->layers[i].media_type = strdup_s(manifest->layers[i]->media_type);
		desc->layers[i].size = manifest->layers[i]->size;
		desc->layers[i].digest = strdup_s(manifest->layers[i]->digest);
	}
	desc->layers_len = manifest->layers_len;
out:
	free_registry_manifest_schema2(manifest);
	manifest = NULL;
	free(err);
	err = NULL;

	return ret;
}

static int parse_manifest_ociv1(pull_descriptor *desc) {
	oci_image_manifest *manifest = NULL;
	parser_error err = NULL;
	int ret = 0;
	size_t i = 0;
	manifest = oci_image_manifest_parse_file(desc->manifest.file, NULL, &err);
	if(manifest == NULL) {
		printf("parse manifest oci v1 failed, err : %s\n", err);
		ret = -1;
		goto out;
	}
	desc->config.media_type = strdup_s(manifest->config->media_type);
	desc->config.digest = strdup_s(manifest->config->digest);
	desc->config.size = manifest->config->size;
	if(manifest->layers_len > MAX_LAYER_NUM) {
		printf("Invalid layer number %zu, maxium is %d\n", manifest->layers_len, MAX_LAYER_NUM);
		ret = -1;
		goto out;
	}
	desc->layers = calloc_s(sizeof(layer_blob), manifest->layers_len);
	if(desc->layers == NULL) {
		printf("out of memory\n");
		ret = -1;
		goto out;
	}

	for(i = 0; i < manifest->layers_len; i++) {
		if(strcmp(manifest->layers[i]->media_type, OCI_IMAGE_LAYER_TAR_GZIP) &&
            strcmp(manifest->layers[i]->media_type, OCI_IMAGE_LAYER_TAR) &&
            strcmp(manifest->layers[i]->media_type, OCI_IMAGE_LAYER_ND_TAR) &&
            strcmp(manifest->layers[i]->media_type, OCI_IMAGE_LAYER_ND_TAR_GZIP)) {
			printf("unsupported layer's media tyoe %s, layer index %zu", manifest->layers[i]->media_type, i);
			ret = -1;
			goto out;
		}
		desc->layers[i].media_type = strdup_s(manifest->layers[i]->media_type);
		desc->layers[i].size = manifest->layers[i]->size;
		desc->layers[i].digest = strdup_s(manifest->layers[i]->digest);
	}
	desc->layers_len = manifest->layers_len;
out:
	free_oci_image_manifest(manifest);
	manifest = NULL;
	free(err);
	err = NULL;
	
	return ret;
}

static int parse_manifest(pull_descriptor* desc) {
	char* media_type = NULL;
	int ret = 0;
	if(desc == NULL) {
		printf("invalid NULL pointer\n");
		return -1;
	}
	media_type = desc->manifest.media_type;
	if(!strcmp(media_type, DOCKER_MANIFEST_SCHEMA2_JSON)) {
		ret = parse_manifest_schema2(desc);
	} else if(!strcmp(media_type, OCI_MANIFEST_V1_JSON)){
		ret = parse_manifest_ociv1(desc);
	} else {
		printf("Unsupported manifest media type %s\n", desc->manifest.media_type);
		return -1;
	}
	if(ret != 0) {
		printf("parse manifest failed, media_type %s\n", desc->manifest.media_type);
	}
	return ret;
}

static int fetch_and_parse_manifest(pull_descriptor *desc) {
	int ret = 0;

	if(desc == NULL) {
		printf("Invalid NULL param\n");
		return -1;
	}

	ret = fetch_manifest(desc);
	if(ret != 0) {
		printf("fetch manifest failed\n");
		goto out;
	}

	ret = parse_manifest(desc);
	if(ret != 0) {
		printf("parse manifest failed\n");
		goto out;
	}
out:
	return ret;
}

static int fetch_config(pull_descriptor* desc) {
	int ret = 0;
	int sret = 0;
	char file[PATH_MAX] = { 0 };
	char path[PATH_MAX] = { 0 };
	if(desc == NULL) {
		printf("invalid NULL pointer\n");
		return -1;
	}
	sret = snprintf(file, sizeof(file), "%s/config", desc->blobpath);
	if(sret < 0 || sret >= sizeof(file)) {
		printf("Failed to sprintf file for config\n");
		return -1;
	}
	sret = snprintf(path, sizeof(path), "/v2/%s/blobs/%s", desc->name, desc->config.digest);
	if(sret < 0 || sret >= sizeof(path)) {
		printf("Failed to sprintf path for config\n");
		ret = -1;
		goto out;
	}
	ret = fetch_data(desc, path, file, desc->config.media_type, desc->config.digest);
	if(ret != 0) {
		printf("registry: Get %s failed\n", path);
		goto out;
	}
	desc->config.file = strdup_s(file);
out:
	return ret;
}

static char *calc_chain_id(char *parent_chain_id, char *diff_id)
{
    int sret = 0; 
    char tmp_buffer[MAX_ID_BUF_LEN] = { 0 }; 
    char* digest = NULL;
    char* full_digest = NULL;

    if (parent_chain_id == NULL || diff_id == NULL) {
        printf("Invalid NULL param\n");
        return NULL;
    }    

    if (strlen(diff_id) <= strlen(SHA256_PREFIX)) {
        printf("Invalid diff id %s found when calc chain id\n", diff_id);
        return NULL;
    }    

    if (strlen(parent_chain_id) == 0) { 
        return strdup_s(diff_id);
    }    

    if (strlen(parent_chain_id) <= strlen(SHA256_PREFIX)) {
        printf("Invalid parent chain id %s found when calc chain id\n", parent_chain_id);
        return NULL;
    }    

    sret = snprintf(tmp_buffer, sizeof(tmp_buffer), "%s+%s", parent_chain_id + strlen(SHA256_PREFIX),
                    diff_id + strlen(SHA256_PREFIX));
    if (sret < 0 || (size_t)sret >= sizeof(tmp_buffer)) {
        printf("Failed to sprintf chain id original string\n");
        return NULL;
    }    

    digest = sha256_digest_str(tmp_buffer);
    if (digest == NULL) {
        printf("Failed to calculate chain id\n");
        goto out;
    }

    full_digest = calc_full_digest(digest);

out:

    free(digest);
    digest = NULL;

    return full_digest;
}

static int parse_docker_config(pull_descriptor* desc) {
	int ret = 0;
	size_t i = 0;
	docker_image_config_v2* config = NULL;
	char* diff_id = NULL;
	char* parent_chain_id = "";
	parser_error err;
	config = docker_image_config_v2_parse_file(desc->config.file, NULL, &err);
	if(config == NULL) {
		printf("parse image config v2 failed\n");
		ret = -1;
		goto out;
	}
	if(config->rootfs == NULL || config->rootfs->diff_ids_len == 0) {
		printf("No rootfd found in config\n");
		ret = -1;
		goto out;
	}
	for(i = 0; i < config->rootfs->diff_ids_len; i++) {
		diff_id = config->rootfs->diff_ids[i];
		desc->layers[i].diff_id = strdup_s(diff_id);
		desc->layers[i].chain_id = calc_chain_id(parent_chain_id, diff_id);
		if(desc->layers[i].chain_id == NULL) {
			printf("calc chain id failed, diff id %s, parent chain id %s\n", diff_id, parent_chain_id);
			ret = -1;
			goto out;
		}
		parent_chain_id = desc->layers[i].chain_id;
	}
	desc->config.create_time = str_to_timestamp(config->created);
out:
	free_docker_image_config_v2(config);
	config = NULL;
	free(err);
	err = NULL;
	return ret;
}

static int parse_oci_config(pull_descriptor *desc) {
	int ret = 0;
	int i = 0;
	parser_error err = NULL;
	oci_image_spec *config = NULL;
	char *diff_id = NULL;
	char *parent_chain_id = "";

	if(desc == NULL) {
		printf("Invalid NULL param\n");
		return -1;
	}

	config = oci_image_spec_parse_file(desc->config.file, NULL, &err);
	if(config == NULL) {
		printf("parse image config v2 failed, err: %s\n", err);
		ret = -1;
		goto out;
	}

	if(config->rootfs == NULL || config->rootfs->diff_ids_len == 0) {
		printf("No rootfs found in config\n");
		ret = -1;
		goto out;
	}

	for(i = 0; i < config->rootfs->diff_ids_len; i++) {
		diff_id = config->rootfs->diff_ids[i];
		desc->layers[i].diff_id = strdup_s(diff_id);
		desc->layers[i].chain_id = calc_chain_id(parent_chain_id, diff_id);
		if(desc->layers[i].chain_id == NULL) {
			printf("calc chain id failed, diff id %s, parent chain id %s\n", diff_id, parent_chain_id);
			ret = -1;
			goto out;
		}
	}
	desc->config.create_time = str_to_timestamp(config->created);
out:
	free_oci_image_spec(config);
	config = NULL;
	free(err);
	err = NULL;

	return ret;
}

static int parse_config(pull_descriptor* desc) {
	int ret = 0;
	char* media_type = NULL;
	char* manifest_media_type = NULL;
	if(desc == NULL) {
		printf("invalid NULL pointer\n");
		return -1;
	}
	media_type = desc->config.media_type;
	manifest_media_type = desc->manifest.media_type;
	if (!strcmp(media_type, DOCKER_IMAGE_V1) || !strcmp(manifest_media_type, DOCKER_MANIFEST_SCHEMA2_JSON)) {
		ret = parse_docker_config(desc);
	} else if(!strcmp(media_type, OCI_IMAGE_V1) || !strcmp(manifest_media_type, OCI_MANIFEST_V1_JSON)) {
		ret = parse_oci_config(desc);
	} else {
		printf("parse config failed, media type %s %s", media_type, manifest_media_type);
		return -1;
	}
	if(ret != 0) {
		printf("parse config failed\n");
		return ret;
	}
	return ret;
}

static int fetch_and_parse_config(pull_descriptor* desc) {
	int ret = 0;
	if(desc == NULL) {
		printf("Invalid NULL param\n");
		return -1;
	}
	ret = fetch_config(desc);
	if(ret != 0) {
		printf("fetch config failed\n");
		return -1;
	}
	ret = parse_config(desc);
	if(ret != 0) {
		printf("parse config failed\n");
		return -1;
	}
	return 0;
}

int fetch_layer(pull_descriptor* desc, size_t index) {
	int ret = 0;
	int sret = 0;
	char file[PATH_MAX] = { 0 };
	char path[PATH_MAX] = { 0 };
	layer_blob* layer = NULL;
	if(index >= desc->layers_len) {
		printf("Invalid layer index\n");
		return -1;
	}
	sret = snprintf(file, sizeof(file), "%s/%zu", desc->blobpath, index);
	if(sret < 0 || (size_t)sret >= sizeof(file)) {
		printf("Failed to sprintf file for layer %zu\n", index);
		return -1;
	}
	layer = &desc->layers[index];
	sret = snprintf(path, sizeof(path), "/v2/%s/blobs/%s", desc->name, layer->digest);
	if(sret < 0 || (size_t)sret >= sizeof(path)) {
		printf("Failed to sprintf path for layer %zu\n", index);
		ret = -1;
		goto out;
	}
	ret = fetch_data(desc, path, file, layer->media_type, layer->digest);
	if(ret != 0) {
		printf("registry: Get %s failed\n", path);
		goto out;
	}
out:
	return ret;
}

static int set_info_to_desc(pull_descriptor *desc, size_t i, char *file) {
	desc->layers[i].file = strdup_s(file); 
	if(desc->layers[i].empty_layer) {
		return 0;
	}
	if(desc->layers[i].already_exist) {
		return 0;
	}
	if(desc->layers[i].diff_id == NULL) {
		printf("layer %ld of image %s have invalid NULL diffid\n", i, desc->image_name);
		return -1;
	}
	if(desc->layers[i].chain_id == NULL) {
		desc->layers[i].chain_id = calc_chain_id(desc->parent_chain_id, desc->layers[i].diff_id);
		if(desc->layers[i].chain_id == NULL) {
			printf("calc chain id failed\n");
			return -1;
		}
	}
	desc->parent_chain_id = desc->layers[i].chain_id;
	return 0;
}

static int register_layer(pull_descriptor *desc, size_t i) {
	struct layer *l = NULL;
	char *id = NULL;
	//cached_layer *cached = NULL;
	if(desc->layers[i].empty_layer) {
		return 0;
	}

	id = without_sha256_prefix(desc->layers[i].chain_id);
	if(id == NULL) {
		printf("layer %ld have NULL digest for image %s\n", i, desc->image_name);
		return -1;
	}
	
	storage_layer_create_opts_t copts = {
		.parent = desc->parent_layer_id,
		.uncompress_digest = desc->layers[i].diff_id,
		.compressed_digest = desc->layers[i].digest,
		.writable = false,
		.layer_data_path = desc->layers[i].file,
	};
	if(storage_layer_create(id, &copts) != 0) {
		printf("create layer %s failed, parent %s, file %s\n", id, desc->parent_layer_id, desc->layers[i].file);
		return -1;
	}
	desc->layers[i].registered = true;
	free(desc->layer_of_hold_refs);
	desc->layer_of_hold_refs = strdup_s(id);
	/*if(desc->parent_layer_id != NULL) {
		printf("clear hold flag failed for layer")
	}*/
	desc->parent_layer_id = id;
	return 0;
}

static int register_layers(pull_descriptor *desc) {
	int ret = 0;
	size_t i = 0;
	for(i = 0; i < desc->layers_len; i++) {
		if(desc->cancel) {
			ret = -1;
			goto out;
		}
		ret = register_layer(desc, i);
		if(ret != 0) {
			printf("register layers for image %s failed\n", desc->image_name);
			goto out;
		}
	}
out:
	if(ret != 0) {
		desc->cancel = true;
	}
	desc->register_layers_complete = true;
	return 0;
}

static int fetch_all(pull_descriptor* desc) {
	size_t i, j;
	int ret, sret;
	char file[PATH_MAX] = { 0 };
	char *parent_chain_id = NULL;
	if(desc == NULL) {
		printf("invalid NULL param\n");
		return -1;
	}
	ret = fetch_and_parse_config(desc);
	if(ret != 0) {
		printf("fetch and parse config failed\n");
		return -1;
	}
	for(i = 0; i < desc->layers_len; i++) {
		parent_chain_id = NULL;
		sret = snprintf(file, sizeof(file), "%s/%zu", desc->blobpath, i);
		if(sret < 0 || (size_t)sret >= sizeof(file)) {
			printf("Failed to sprintf file for layer %ld\n", i);
			ret = -1;
			break;
		}
		sret = set_info_to_desc(desc, i, file);
		if(sret != 0) {
			printf("set info to desc failed\n");
			ret = -1;
			break;
		}
		sret = fetch_layer(desc, i);
		if(sret != 0) {
			printf("fetch layer %zu failed\n", i);
			break;
		}

	}
	if(sret != 0) {
		return ret;
	}
	register_layers(desc);
	return ret;
}

static int set_loaded_time(pull_descriptor *desc, char *image_id) {
	int ret = 0;
	types_timestamp_t now = { 0 };
	if(!get_now_time_stamp(&now)) {
		ret = -1;
		printf("get now time stamp failed\n");
		goto out;
	}
	ret = storage_img_set_loaded_time(image_id, &now);
	if(ret != 0) {
		printf("set loaded time failed\n");
		goto out;
	}
out:
	return ret;
}

static int set_manifest(pull_descriptor *desc, char *image_id) {
	int ret = 0;
	char *manifest_str = NULL;
	if(desc == NULL) {
		printf("Invalid NULL pointer\n");
		return -1;
	}
	manifest_str = read_text_file(desc->manifest.file);
	if(manifest_str == NULL) {
		printf("read file %s content failed\n", desc->manifest.file);
		ret = -1;
		goto out;
	}
	ret = storage_img_set_big_data(image_id, MANIFEST_BIG_DATA_KEY, manifest_str);
	if(ret != 0) {
		printf("set big data failed\n");
		goto out;
	}
out:
	free(manifest_str);
	manifest_str = NULL;
	return ret;
}

static int set_config(pull_descriptor* desc, char* image_id) {
	int ret = 0;
	char* config_str = NULL;
	if(desc == NULL) {
		printf("Invalid NULL pointer\n");
		return -1;
	}
	config_str = read_text_file(desc->config.file);
	if(config_str == NULL) {
		printf("read file %s content failed\n", desc->config.file);
		ret = -1;
		goto out;
	}
	ret = storage_img_set_big_data(image_id, desc->config.digest, config_str);
	if(ret != 0) {
		printf("set big data failed\n");
		goto out;
	}
out:
	free(config_str);
	config_str = NULL;
	return ret;
}

static int create_image(pull_descriptor* desc, char* image_id, bool* reuse) {
	int ret = 0;
	size_t top_layer_index = 0;
	struct storage_img_create_options opts = { 0 };
	char* top_layer_id = NULL;
	char* pre_top_layer = NULL;
	
	if(image_id == NULL || reuse == NULL) {
		printf("invalid NULL pointer\n");
		return -1;
	}
	top_layer_index = desc->layers_len - 1;
	opts.create_time = &desc->config.create_time;
	opts.digest = desc->manifest.digest;
	top_layer_id = without_sha256_prefix(desc->layers[top_layer_index].chain_id);
	if(top_layer_id == NULL) {
		ret = -1;
		goto out;
	}
	*reuse = false;
	ret = storage_img_create(image_id, top_layer_id, NULL, &opts);
	if(ret != 0) {
		printf("storage_img_create err!\n");
		goto out;
	}
	ret = image_store_add_name(image_id, desc->dest_image_name);
	if(ret != 0) {
		printf("add image name failed\n");
		goto out;
	}

out:
	return ret;
}

static int register_image(pull_descriptor* desc) {
	int ret = 0;
	char* image_id = NULL;
	bool image_created = false;
	bool reuse = false;
	if(desc == NULL) {
		printf("invalid NULL pointer\n");
		return -1;
	}
	image_id = (char*)without_sha256_prefix(desc->config.digest);
	if(image_id == NULL) {
		return -1;
	}
	ret = create_image(desc, image_id, &reuse);
	if(ret != 0) {
		printf("create image %s failed\n", desc->image_name);
		goto out;
	}
	desc->rollback_layers_on_failure = false;
	image_created = true;
	ret = set_config(desc, image_id);
	if(ret != 0) {
		printf("set image config for image %s failed\n", desc->image_name);
		goto out;
	}
	ret = set_manifest(desc, image_id);
	if(ret != 0) {
		printf("set manifest for image %s failed\n", desc->image_name);
		goto out;
	}
	ret = set_loaded_time(desc, image_id);
	if(ret != 0) {
		printf("set loaded time for image %s failed\n", desc->image_name);
		goto out;
	}
	ret = storage_img_set_image_size(image_id);
	if(ret != 0) {
		printf("set image size failed for %s failed\n", desc->image_name);
		goto out;
	}
out:
	if(ret != 0 && image_created) {
		if(storage_img_delete(image_id, true)) {
			printf("delete image %s failed\n", image_id);
		}
	} else {
		printf("created img with id %s\n", image_id);
	}
	return ret;
}

static bool reuse_image(pull_descriptor *desc) {
	image_summary *summary = NULL;
	bool reuse = false;
	char *id = NULL;

	summary = storage_img_get_summary(desc->dest_image_name);
	if(summary == NULL || desc->config.digest == NULL || summary->id == NULL) {
		goto out;
	}

	id = without_sha256_prefix(desc->config.digest);
	if(id == NULL) {
		goto out;
	}

	if(!strcmp(id, summary->id)) {
		printf("image %s with id %s already exist, ignore pulling\n", desc->image_name, summary->id);
		reuse = true;
	}

out:
	free_image_summary(summary);
	return reuse;
}

static int registry_fetch(pull_descriptor *desc, bool *reuse) {
	int ret = 0;
	if(desc == NULL || reuse == NULL) {
		printf("Invalid NULL param\n");
		return -1;
	}
	ret = fetch_and_parse_manifest(desc);
	if(ret != 0) {
		printf("fetch ans parse manifest failed for image %s\n", desc->image_name);
		goto out;
	}
	*reuse = reuse_image(desc);
	if(*reuse) {
		goto out;
	}
	ret = fetch_all(desc);
	if(ret != 0)
		return -1;


	/*if(check_time_valid(desc) != 0) {
		ret = -1;
		goto out;
	}*/
out:
	return ret;
}

void free_challenge(challenge *c)
{
    if (c == NULL) {
        return;
    }

    free(c->schema);
    c->schema = NULL;
    free(c->realm);
    c->realm = NULL;
    free(c->service);
    c->service = NULL;
    free(c->cached_token);
    c->cached_token = NULL;
    c->expires_time = 0;
}

void free_layer_blob(layer_blob *layer)
{
    if (layer == NULL) {
        return;
    }
    layer->empty_layer = false;
    free(layer->media_type);
    layer->media_type = NULL;
    layer->size = 0;
    free(layer->digest);
    layer->digest = NULL;
    free(layer->diff_id);
    layer->diff_id = NULL;
    free(layer->chain_id);
    layer->chain_id = NULL;
    free(layer->file);
    layer->file = NULL;
    layer->already_exist = false;
}

void free_pull_desc(pull_descriptor *desc) {
	int i = 0;

	if(desc == NULL) {
		return;
	}
	free(desc->dest_image_name);
	free(desc->image_name);
	free(desc->host);
	free(desc->name);
	free(desc->tag);
	free(desc->username);
	free(desc->password);
	if(desc->auths_dir != NULL)
		free(desc->auths_dir);

    desc->use_decrypted_key = false;
    desc->cert_loaded = false;
	if(desc->ca_file != NULL)
    	free(desc->ca_file);
	if(desc->cert_file != NULL)
    	free(desc->cert_file);
	if(desc->key_file != NULL)
    	free(desc->key_file);
	if(desc->certs_dir != NULL)
    	free(desc->certs_dir);
	if(desc->errmsg != NULL)
    	free(desc->errmsg);
    free(desc->blobpath);
    free(desc->protocol);
    desc->skip_tls_verify = false;
    free(desc->scope);

    for (i = 0; i < CHALLENGE_MAX; i++) {
        free_challenge(&desc->challenges[i]);
    }
    free_array(desc->headers);

    free(desc->manifest.media_type);
    desc->manifest.size = 0;
    free(desc->manifest.digest);
    free(desc->manifest.file);
    free(desc->config.media_type);
    desc->config.size = 0;
    free(desc->config.digest);
    free(desc->config.file);
	desc->config.create_time.has_seconds = 0;
    desc->config.create_time.seconds = 0;
    desc->config.create_time.has_nanos = 0;
    desc->config.create_time.nanos = 0;
    for (i = 0; i < desc->layers_len; i++) {
        free_layer_blob(&desc->layers[i]);
    }
    free(desc->layers);
    desc->layers = NULL;
    desc->layers_len = 0;

	if(desc->layer_of_hold_refs != NULL)
    	free(desc->layer_of_hold_refs);

#ifdef ENABLE_IMAGE_SEARCH
    free(desc->search_name);
    desc->search_name = NULL;
#endif
    free(desc);
}

static void clear_tmp_dirs() {
	int ret = 0;
	char tmppath[PATH_MAX] = { 0 };
	
	ret = sprintf(tmppath, "%s/tmpdir", _root_dir);
	if(ret < 0 || ret > PATH_MAX) {
		printf("sprintf for tmpdir error\n");
		return;
	}

	ret = recursive_remove_path(tmppath);
	if(ret != 0) {
		printf("remove path error\n");
	}
	return;
}

int registry_pull(registry_pull_options *pull_options) {
	int ret = 0;
	pull_descriptor* desc = NULL;
	bool reuse = false;
	
	if(pull_options == NULL || pull_options->image_name == NULL) {
		printf("Invalid NULL param\n");
		return -1;
	}
	desc = common_calloc_s(sizeof(pull_descriptor));
	if(desc == NULL) {
		printf("Out of memory\n");
		return -1;
	}
	ret = prepare_pull_desc(desc, pull_options);
	if(ret != 0) {
		printf("registry prepare failed\n");
		ret = -1;
		goto out;
	}
	ret = registry_fetch(desc, &reuse);
	if(ret != 0) {
		printf("error fetching %s\n", pull_options->image_name);
		ret = -1;
		goto out;
	}
	if(!reuse) {
		ret = register_image(desc);
		if(ret != 0) {
			printf("error register image %s to store\n", pull_options->image_name);
			ret = -1;
			goto out;
		}
	}
out:
	clear_tmp_dirs();
	free_pull_desc(desc);
	return ret;
}

void free_registry_pull_options(registry_pull_options *options)
{
    if (options == NULL) {
        return;
    }
	if(options->auth.username != NULL) {
		free(options->auth.username);
		free(options->auth.password);
	}
    free(options->image_name);
    options->image_name = NULL;
    free(options->dest_image_name);
    options->dest_image_name = NULL;
    free(options);
    return;
}

