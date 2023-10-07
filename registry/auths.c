#include "auths.h"
#include "../http/http.h"
static char* g_auth_path = DEFAULT_AUTH_DIR "/" AUTH_FILE_NAME;

//registry_token* make_registry_token (yajl_val tree, const struct parser_context *ctx, parser_error *err)
//{
//    __auto_cleanup(free_registry_token) registry_token *ret = NULL;
//    *err = NULL;
//    (void) ctx;  /* Silence compiler warning.  */
//    if (tree == NULL)
//    	return NULL;
//    ret = calloc (1, sizeof (*ret));
//    if (ret == NULL)
//    	return NULL;
//    do  
//      {   
//        yajl_val val = get_val (tree, "token", yajl_t_string);
//        if (val != NULL)
//          {
//            char *str = YAJL_GET_STRING (val);
//            ret->token = strdup (str ? str : "");
//            if (ret->token == NULL)
//              {
//                return NULL;
//              }
//          }
//      }   
//    while (0);
//    do  
//      {   
//        yajl_val val = get_val (tree, "access_token", yajl_t_string);
//        if (val != NULL)
//          {
//            char *str = YAJL_GET_STRING (val);
//            ret->access_token = strdup (str ? str : "");
//            if (ret->access_token == NULL)
//              {
//                return NULL;
//              }
//          }
//      }   
//    while (0);
//	do
//      {
//        yajl_val val = get_val (tree, "expires_in", yajl_t_number);
//        if (val != NULL)
//          {
//            int invalid = common_safe_uint32 (YAJL_GET_NUMBER (val), &ret->expires_in);
//            if (invalid)
//              {
//                if (asprintf (err, "Invalid value '%s' with type 'uint32' for key 'expires_in': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
//                    *err = strdup ("error allocating memory");
//                return NULL;
//            }
//        }
//      }
//    while (0);
//    do
//      {
//        yajl_val val = get_val (tree, "issued_at", yajl_t_string);
//        if (val != NULL)
//          {
//            char *str = YAJL_GET_STRING (val);
//            ret->issued_at = strdup (str ? str : "");
//            if (ret->issued_at == NULL)
//              {
//                return NULL;
//              }
//          }
//      }
//    while (0);
//    do
//      {
//        yajl_val val = get_val (tree, "refresh_token", yajl_t_string);
//        if (val != NULL)
//          {
//            char *str = YAJL_GET_STRING (val);
//            ret->refresh_token = strdup (str ? str : "");
//            if (ret->refresh_token == NULL)
//              {
//                return NULL;
//              }
//          }
//      }
//    while (0);
//    if (tree->type == yajl_t_object)
//      {
//        size_t i;
//        size_t j = 0;
//        size_t cnt = tree->u.object.len;
//        yajl_val resi = NULL;
//
//        if (ctx->options & OPT_PARSE_FULLKEY)
//          {
//            resi = calloc (1, sizeof(*tree));
//            if (resi == NULL)
//              {
//                return NULL;
//              }
//            resi->type = yajl_t_object;
//            resi->u.object.keys = calloc (cnt, sizeof (const char *));
//            if (resi->u.object.keys == NULL)
//              {
//                yajl_tree_free (resi);
//                return NULL;
//              }
//            resi->u.object.values = calloc (cnt, sizeof (yajl_val));
//            if (resi->u.object.values == NULL)
//              {
//                yajl_tree_free (resi);
//                return NULL;
//              }
//          }
//
//        for (i = 0; i < tree->u.object.len; i++)
//          {
//            if (strcmp (tree->u.object.keys[i], "token")
//                && strcmp (tree->u.object.keys[i], "access_token")
//                && strcmp (tree->u.object.keys[i], "expires_in")
//                && strcmp (tree->u.object.keys[i], "issued_at")
//                && strcmp (tree->u.object.keys[i], "refresh_token"))
//              {
//                if (ctx->options & OPT_PARSE_FULLKEY)
//                  {
//                    resi->u.object.keys[j] = tree->u.object.keys[i];
//                    tree->u.object.keys[i] = NULL;
//                    resi->u.object.values[j] = tree->u.object.values[i];
//                    tree->u.object.values[i] = NULL;
//                    resi->u.object.len++;
//                  }
//                j++;
//              }
//          }
//        if (ctx->options & OPT_PARSE_STRICT)
//          {
//            if (j > 0 && ctx->errfile != NULL)
//                (void) fprintf (ctx->errfile, "WARNING: unknown key found\n");
//          }
//        if (ctx->options & OPT_PARSE_FULLKEY)
//            ret->_residual = resi;
//      }
//    return move_ptr (ret);
//}
//
//registry_token* registry_token_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)
//{
//    registry_token *ptr = NULL;
//    __auto_cleanup(yajl_tree_free) yajl_val tree = NULL;
//    char errbuf[1024];
//    struct parser_context tmp_ctx = { 0 };
//
//    if (jsondata == NULL || err == NULL)
//    	return NULL;
//
//    *err = NULL;
//    if (ctx == NULL)
//    	ctx = (const struct parser_context *)(&tmp_ctx);
//
//    tree = yajl_tree_parse (jsondata, errbuf, sizeof (errbuf));
//    if (tree == NULL)
//      {   
//        if (asprintf (err, "cannot parse the data: %s", errbuf) < 0)
//            *err = strdup ("error allocating memory");
//        return NULL;
//      }   
//    ptr = make_registry_token (tree, ctx, err);
//    return ptr;
//}

static char *encode_auth(const char *username, const char *password)
{
    char *auth = NULL;
    size_t auth_len = 0;
    char *auth_base64 = NULL;
    int ret = 0;
    int nret = 0;

    if (username == NULL || password == NULL) {
        printf("Invalid NULL pointer");
        return NULL;
    }   

    auth_len = strlen(username) + strlen(":") + strlen(password);
    auth = calloc(1, auth_len + 1); 
    if (auth == NULL) {
        ERROR("out of memory");
        return NULL;
    }   
    // username:password
    nret = snprintf(auth, auth_len + 1, "%s:%s", username, password);
    if (nret < 0 || (size_t)nret > auth_len) {
        ret = -1; 
        ERROR("Failed to sprintf username and password");
        goto out;
    }   

    nret = base64_encode((unsigned char *)auth, strlen(auth), &auth_base64);
    if (nret < 0) {
        ret = -1; 
        ERROR("Encode auth to base64 failed");
        goto out;
    }   

out:
    free(auth);
    auth = NULL;

    if (ret != 0) {
        free(auth_base64);
        auth_base64 = NULL;
    }   

    return auth_base64;
}

char *auth_header_str(const char *schema, const char *value)
{
    int ret = 0;
    int sret = 0;
    char *auth_header = NULL;
    size_t auth_header_len = 0;

    if (schema == NULL || value == NULL) {
        printf("Invalid NULL pointer");
        return NULL;
    }

    // Auth header's format example:
    // Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l
    auth_header_len = strlen("Authorization") + strlen(": ") + strlen(schema) + strlen(" ") + strlen(value) + 1;
    auth_header = calloc(1, auth_header_len);
    if (auth_header == NULL) {
        printf("out of memory");
        ret = -1;
        goto out;
    }

    sret = snprintf(auth_header, auth_header_len, "Authorization: %s %s", schema, value);
    if (sret < 0 || (size_t)sret >= auth_header_len) {
        ret = -1;
        printf("Failed to sprintf authorization");
        goto out;
    }

out:
    if (ret != 0) {
        free(auth_header);
        auth_header = NULL;
    }
    return auth_header;
}

char *build_get_token_url(challenge *c, char *username, char *scope)
{
    char *url = NULL;
    size_t url_len = 0;

    // Do not check username, it can be NULL
    if (c == NULL || c->realm == NULL) {
        printf("Invalid NULL pointer");
        return NULL;
    }

    // url format example:
    // https://auth.isula.org/token?account=name&service=registry.isula.org&scope=repository:samalba/my-app:pull
    url_len += strlen(c->realm) + strlen("?");
    if (username != NULL) {
        url_len += strlen("account=") + strlen(username) + strlen("&");
    }
    if (c->service != NULL) {
        url_len += strlen("service=") + strlen(c->service) + strlen("&");
    }
    if (scope != NULL) {
        url_len += strlen("scope=") + strlen(scope) + strlen("&");
    }

    url = calloc(1, url_len);
    if (url == NULL) {
        printf("out of memory");
        return NULL;
    }

    strcat(url, c->realm);
    if (username != NULL || c->service != NULL || scope != NULL) {
        strcat(url, "?");
    }

    if (username != NULL) {
        strcat(url, "account=");
        strcat(url, username);
        if (c->service != NULL || scope != NULL) {
            strcat(url, "&");
        }
    }

    if (c->service != NULL) {
        strcat(url, "service=");
        strcat(url, c->service);
        if (scope != NULL) {
            strcat(url, "&");
        }
    }

    if (scope != NULL) {
        strcat(url, "scope=");
        strcat(url, scope);
    }

    return url;
}

int setup_auth_basic(pull_descriptor *desc, char ***custom_headers)
{
    int ret = 0;
    char *auth_header = NULL;

    if (desc == NULL || custom_headers == NULL) {
        printf("Invalid NULL pointer");
        return -1;
    }

    // Setup auth config only when username and password are provided.
    if (desc->username == NULL || desc->password == NULL) {
        return 0;
    }

    auth_header = basic_auth_header("Basic", desc->username, desc->password);
    if (auth_header == NULL) {
        ret = -1;
        goto out;
    }
    ret = array_append(custom_headers, (const char *)auth_header);
    if (ret != 0) {
        printf("append custom headers failed");
        goto out;
    }

out:
    free(auth_header);
    auth_header = NULL;

    return ret;
}

int setup_get_token_options(pull_descriptor *desc, struct http_get_options *options, const char *url)
{
    int ret = 0;

    if (desc == NULL || options == NULL) {
        printf("Invalid NULL pointer");
        return -1;
    }

    // Add https related options
    ret = setup_ssl_config(desc, options, url);
    if (ret != 0) {
        printf("Failed setup ssl config");
        ret = -1;
        goto out;
    }

    ret = setup_auth_basic(desc, &options->custom_headers);
    if (ret != 0) {
        printf("dup headers failed");
        ret = -1;
        goto out;
    }

    options->debug = false;

out:

    return ret;
}

char *get_url_host(const char *url)
{
    char *tmp_url = NULL;
    char *prefix = NULL;
    char *end = NULL;
    char *host = NULL;

    if (url == NULL) {
        printf("Invalid NULL pointer");
        return NULL;
    }

    if (has_prefix(url, HTTPS_PREFIX)) {
        prefix = HTTPS_PREFIX;
    } else if (has_prefix(url, HTTP_PREFIX)) {
        prefix = HTTP_PREFIX;
    } else {
        printf("Unexpected url %s, it must be prefixed with %s or %s", url, HTTP_PREFIX, HTTPS_PREFIX);
        goto out;
    }

    tmp_url = util_strdup_s(url);
    end = strchr(tmp_url + strlen(prefix), '/');
    if (end != NULL) {
        *end = 0;
    }

    host = strdup_s(tmp_url + strlen(prefix));
out:
    free(tmp_url);
    tmp_url = NULL;

    return host;
}

int setup_ssl_config(pull_descriptor *desc, struct http_get_options *options, const char *url)
{
    int ret = 0;
    char *host = NULL;

    if (desc == NULL || url == NULL || options == NULL) {
        printf("Invalid NULL pointer");
        return -1; 
    }   

    // Add only https related options
    if (!has_prefix(url, HTTPS_PREFIX)) {
        return 0;
    }   

    host = get_url_host(url);
    if (host == NULL) {
        printf("Get host from url failed");
        return -1; 
    }   

    // If target is registry server, we can save ssl related config to avoid load it again next time.
    if (!strcmp(host, desc->host)) {
        if (!desc->cert_loaded) {
            ret = certs_load(host, desc->use_decrypted_key, &desc->ca_file, &desc->cert_file, &desc->key_file);
            if (ret != 0) {
                ret = -1; 
                goto out;
            }
            desc->cert_loaded = true;
        }
        options->ca_file = util_strdup_s(desc->ca_file);
        options->cert_file = util_strdup_s(desc->cert_file);
        options->key_file = util_strdup_s(desc->key_file);
    } else {
        ret = certs_load(host, desc->use_decrypted_key, &options->ca_file, &options->cert_file, &options->key_file);
        if (ret != 0) {
            ret = -1; 
            goto out;
        }
    }   

    options->ssl_verify_peer = !desc->skip_tls_verify;
    options->ssl_verify_host = !desc->skip_tls_verify;
out:

    free(host);
    host = NULL;

    return ret;
}

int http_request_get_token(pull_descriptor* desc, challenge* c, char** output) {
	char* url = NULL;
	int ret = 0;
    struct http_get_options *options = NULL;

    if (desc == NULL || c == NULL || output == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    options = calloc(1, sizeof(struct http_get_options));
    if (options == NULL) {
        ERROR("Failed to malloc http_get_options");
        ret = -1;
        goto out;
    }

    memset(options, 0x00, sizeof(struct http_get_options));
    options->with_body = 1;
    options->with_head = 0;

    ret = setup_get_token_options(desc, options, c->realm);
    if (ret != 0) {
        ERROR("Failed setup common options");
        ret = -1;
        goto out;
    }

    url = build_get_token_url(c, desc->username, desc->scope);
    if (url == NULL) {
        ret = -1;
        goto out;
    }

    ret = http_request_buf_options(desc, options, url, output);
    if (ret) {
        ERROR("Failed to get http request");
        ret = -1;
        goto out;
    }

out:
    free(options);
    options = NULL;
    free(url);
    url = NULL;

    return ret;
}

char *basic_auth_header(const char *schema, const char *username, const char *password)
{
    int ret = 0;
    char *auth_base64 = NULL;
    char *auth_header = NULL;

    if (username == NULL || password == NULL) {
        ERROR("Invalid NULL pointer");
        return NULL;
    }   

    auth_base64 = encode_auth(username, password);
    if (auth_base64 == NULL) {
        return NULL;
    }   

    auth_header = auth_header_str(schema, auth_base64);
    if (auth_header == NULL) {
        ret = -1; 
        goto out;
    }   

out:
    free(auth_base64);
    auth_base64 = NULL;
    if (ret != 0) {
        free(auth_header);
        auth_header = NULL;
    }   

    return auth_header;
}

int get_bearer_token(pull_descriptor *desc, challenge *c) 
{
    int ret = 0;
    char *output = NULL;
    time_t now = time(NULL);
    registry_token *token = NULL;
    parser_error err = NULL;

    if (desc == NULL || c == NULL) {
        ERROR("Invalid NULL pointer");
        return -1; 
    }   

    // Token have not expired, reuse it.
    if (c->cached_token != NULL && c->expires_time != 0 && c->expires_time < now) {
        return 0;
    }   

    free(c->cached_token);
    c->cached_token = NULL;
    c->expires_time = 0;

    ret = http_request_get_token(desc, c, &output);
    if (ret != 0 || output == NULL) {
        ERROR("http request get token failed, result is %d", ret);
        ret = -1; 
        goto out;
    }   

    token = registry_token_parse_data(output, NULL, &err);
    if (token == NULL) {
        ret = -1; 
        ERROR("parse token from response failed due to err: %s", err);
        goto out;
    }   

    if (token->token != NULL) {
    	c->cached_token = strdup_s(token->token);
    } else if (token->access_token != NULL) {
    	c->cached_token = strdup_s(token->access_token);
    } else {
        ret = -1; 
        ERROR("no valid token found");
        goto out;
    }   

    if (token->expires_in > MIN_TOKEN_EXPIRES_IN) {
        c->expires_time = time(NULL) + token->expires_in;
    } else {
        c->expires_time = MIN_TOKEN_EXPIRES_IN;
    }

out:
    free(err);
    err = NULL;
    free(token);
    token = NULL;
    free(output);
    output = NULL;

    return ret;
}

static int setup_auth_challenges(pull_descriptor *desc, char ***custom_headers)
{
    int ret = 0;
    int i = 0;
    char *auth_header = NULL;
    size_t count = 0;

    if (desc == NULL || custom_headers == NULL) {
        printf("Invalid NULL pointer");
        return -1;
    }

    for (i = 0; i < CHALLENGE_MAX; i++) {
        if (desc->challenges[i].schema == NULL || desc->challenges[i].realm == NULL) {
            continue;
        }
        if (!strcasecmp(desc->challenges[i].schema, "Basic")) {
            // Setup auth config only when username and password are provided.
            if (desc->username == NULL || desc->password == NULL) {
                printf("username or password not found while challenges is basic, try other challenges");
                continue;
            }

            auth_header = basic_auth_header("Basic", desc->username, desc->password);
            if (auth_header == NULL) {
                printf("encode basic auth header failed");
                ret = -1;
                goto out;
            }
        } else if (!strcasecmp(desc->challenges[i].schema, "Bearer")) {
            ret = get_bearer_token(desc, &desc->challenges[i]);
            if (ret != 0) {
                printf("get bearer token failed");
                //isulad_try_set_error_message("authentication failed");
                goto out;
            }

            auth_header = auth_header_str("Bearer", desc->challenges[i].cached_token);
            if (auth_header == NULL) {
                ret = -1;
                goto out;
            }
        } else {
            printf("Unsupported schema %s", desc->challenges[i].schema);
            continue;
        }
		ret = array_append(custom_headers, (const char *)auth_header);
        if (ret != 0) {
            printf("append custom headers failed");
            ret = -1;
            goto out;
        }
        count++;
        free(auth_header);
        auth_header = NULL;
    }

    if (count == 0) {
        printf("No valid challenge found, try continue to send url without auth");
    }

out:
    free(auth_header);
    auth_header = NULL;

    return ret;
}

