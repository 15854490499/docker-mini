#ifndef __REGISTRY_H__
#define __REGISTRY_H__

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "registry_auths.h"
#include "registry_token.h"
#include "registry_manifest_schema2.h"
#include "registry_manifest_list.h"
#include "docker_image_config_v2.h"
#include "docker_image_history.h"
#include "docker_image_rootfs.h"
#include "timestamp.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_AUTH_DIR_MODE 0700
#define AUTH_FILE_NAME "auths.json"
#define AUTH_FILE_MODE 0600
#define MAX_AUTHS_LEN 65536
#define CHALLENGE_MAX 8
#define MAX_LAYER_NUM 125
#define ROOTFS_TYPE "layers"

#define DOCKER_API_VERSION_HEADER "Docker-Distribution-Api-Version: registry/2.0"

#define _root_dir "/var/lib/docker-mini"
//#define PATH_MAX 1024
#define MAX_ACCEPT_LEN 128
#define RETRY_TIMES 5

#define DOCKER_API_VERSION_HEADER "Docker-Distribution-Api-Version: registry/2.0"
#define DOCKER_MANIFEST_SCHEMA2_JSON "application/vnd.docker.distribution.manifest.v2+json"
#define DOCKER_MANIFEST_SCHEMA2_LIST "application/vnd.docker.distribution.manifest.list.v2+json"
#define DOCKER_MANIFEST_SCHEMA1_JSON "application/vnd.docker.distribution.manifest.v1+json"
#define DOCKER_MANIFEST_SCHEMA1_PRETTYJWS "application/vnd.docker.distribution.manifest.v1+prettyjws"
#define DOCKER_IMAGE_LAYER_TAR_GZIP "application/vnd.docker.image.rootfs.diff.tar.gzip"
#define DOCKER_IMAGE_LAYER_FOREIGN_TAR_GZIP "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
#define DOCKER_IMAGE_V1 "application/vnd.docker.container.image.v1+json"
#define MEDIA_TYPE_APPLICATION_JSON "application/json"
#define OCI_MANIFEST_V1_JSON "application/vnd.oci.image.manifest.v1+json"
#define OCI_INDEX_V1_JSON "application/vnd.oci.image.index.v1+json"
#define OCI_IMAGE_V1 "application/vnd.oci.image.config.v1+json"
#define OCI_IMAGE_LAYER_TAR "application/vnd.oci.image.layer.v1.tar"
#define OCI_IMAGE_LAYER_TAR_GZIP "application/vnd.oci.image.layer.v1.tar+gzip"
#define OCI_IMAGE_LAYER_ND_TAR "application/vnd.oci.image.layer.nondistributable.v1.tar"
#define OCI_IMAGE_LAYER_ND_TAR_GZIP "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"

typedef struct {
	char* schema;
	char* realm;
	char* service;
	char* cached_token;
	time_t expires_time;
} challenge;

typedef struct {
	char* username;
	char* password;
} registry_auth;

typedef struct {
	char* image_name;
	char* dest_image_name;
	registry_auth auth;
	bool skip_tls_verify;
	bool insecure_registry;
} registry_pull_options;

typedef struct {
    char *media_type;
    size_t size;
    char *digest;
    // Downloaded file path
    char *file;
} manifest_blob;

typedef struct {
    char *media_type;
    size_t size;
    char *digest;
    // Downloaded file path
    char *file;
    types_timestamp_t create_time;
    bool complete;
    int result;
} config_blob;

typedef struct {
    bool empty_layer;
    char* media_type;
    // blob size
    size_t size;
    // compressed digest
    char* digest;
    // uncompressed digest
    char* diff_id;
    // use chainID as layerID
    char* chain_id;
    // Downloaded file path
    char* file;
    // already exist on local store
    bool already_exist;
    // layer have registered to loacal store, this flag used to rollback
    bool registered;
} layer_blob;

typedef struct _pull_descriptor_{
    char *image_name;
    char *dest_image_name;
    char *host;
    char *name;
    char *tag;

    char *username;
    char *password;
    char *auths_dir;

    bool use_decrypted_key;
    bool cert_loaded;
    char *ca_file;
    char *cert_file;
    char *key_file;
    char *certs_dir;

    int pulling_number;
    bool cancel;
    char *errmsg;

    char *blobpath;
    char *protocol;
    bool skip_tls_verify;
    bool insecure_registry;
    char *scope;
    //pthread_mutex_t challenges_mutex;
    //bool challenges_mutex_inited;
    challenge challenges[CHALLENGE_MAX];
    // This is temporary field. Once http request is performed, it is cleared
    char **headers;

    char *layer_of_hold_refs;

    // Image blobs downloaded
    manifest_blob manifest;
    config_blob config;
    layer_blob *layers;
    size_t layers_len;

    bool rollback_layers_on_failure;
    bool register_layers_complete;
    // used to calc chain id
    char *parent_chain_id;
    // used to register layer
    char *parent_layer_id;
    //pthread_mutex_t mutex;
    //bool mutex_inited;
    //pthread_cond_t cond;
    bool cond_inited;
#ifdef ENABLE_IMAGE_SEARCH
    //used to search image
    char *search_name;
    uint32_t limit;
#endif
} pull_descriptor;

int registry_pull(registry_pull_options *pull_options);
void free_pull_desc(pull_descriptor *desc);
void free_challenge(challenge *c);
void free_layer_blob(layer_blob *layer);
void free_registry_pull_options(registry_pull_options *options);
#ifdef __cplusplus
}
#endif

#endif
