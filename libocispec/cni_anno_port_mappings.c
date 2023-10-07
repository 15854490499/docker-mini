/* Generated from anno_port_mappings.json. Do not edit!  */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include "read-file.h"
#include "cni_anno_port_mappings.h"

#define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)
#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)
define_cleaner_function (cni_anno_port_mappings_element *, free_cni_anno_port_mappings_element)
cni_anno_port_mappings_element *
make_cni_anno_port_mappings_element (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_cni_anno_port_mappings_element) cni_anno_port_mappings_element *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "hostPort", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int32 (YAJL_GET_NUMBER (val), &ret->host_port);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'int32' for key 'hostPort': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->host_port_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "containerPort", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int32 (YAJL_GET_NUMBER (val), &ret->container_port);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'int32' for key 'containerPort': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->container_port_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "protocol", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->protocol = strdup (str ? str : "");
            if (ret->protocol == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "hostIP", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->host_ip = strdup (str ? str : "");
            if (ret->host_ip == NULL)
              return NULL;
          }
      }
    while (0);
    return move_ptr (ret);
}

void
free_cni_anno_port_mappings_element (cni_anno_port_mappings_element *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr->protocol);
    ptr->protocol = NULL;
    free (ptr->host_ip);
    ptr->host_ip = NULL;
    free (ptr);
}

yajl_gen_status
gen_cni_anno_port_mappings_element (yajl_gen g, const cni_anno_port_mappings_element *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->host_port_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("hostPort"), 8 /* strlen ("hostPort") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->host_port)
            num = (long long int)ptr->host_port;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->container_port_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("containerPort"), 13 /* strlen ("containerPort") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->container_port)
            num = (long long int)ptr->container_port;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->protocol != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("protocol"), 8 /* strlen ("protocol") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->protocol != NULL)
            str = ptr->protocol;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->host_ip != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("hostIP"), 6 /* strlen ("hostIP") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->host_ip != NULL)
            str = ptr->host_ip;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    stat = yajl_gen_map_close ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    return yajl_gen_status_ok;
}


define_cleaner_function (cni_anno_port_mappings_container *, free_cni_anno_port_mappings_container)
cni_anno_port_mappings_container
*make_cni_anno_port_mappings_container (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_cni_anno_port_mappings_container) cni_anno_port_mappings_container *ptr = NULL;
    size_t i, alen;
     (void) ctx;
     if (tree == NULL || err == NULL || YAJL_GET_ARRAY (tree) == NULL)
      return NULL;
    *err = NULL;
    alen = YAJL_GET_ARRAY_NO_CHECK (tree)->len;
    if (alen == 0)
      return NULL;
    ptr = calloc (1, sizeof (cni_anno_port_mappings_container));
    if (ptr == NULL)
      return NULL;
    ptr->items = calloc (alen + 1, sizeof(*ptr->items));
    if (ptr->items == NULL)
      return NULL;
    ptr->len = alen;


    for (i = 0; i < alen; i++)
      {
        yajl_val work = YAJL_GET_ARRAY_NO_CHECK (tree)->values[i];
        ptr->items[i] = make_cni_anno_port_mappings_element (work, ctx, err);
        if (ptr->items[i] == NULL)
          return NULL;


      }
    return move_ptr(ptr);
}


void free_cni_anno_port_mappings_container (cni_anno_port_mappings_container *ptr)
{
    size_t i;

    if (ptr == NULL)
        return;

    for (i = 0; i < ptr->len; i++)
      {
          free_cni_anno_port_mappings_element (ptr->items[i]);
          ptr->items[i] = NULL;

      }

    free (ptr->items);
    ptr->items = NULL;


    free (ptr);
}
yajl_gen_status gen_cni_anno_port_mappings_container (yajl_gen g, const cni_anno_port_mappings_container *ptr, const struct parser_context *ctx,
                       parser_error *err)
{
    yajl_gen_status stat;
    size_t i;

    if (ptr == NULL)
        return yajl_gen_status_ok;
    *err = NULL;


    stat = yajl_gen_array_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    for (i = 0; i < ptr->len; i++)
      {
      {
            stat = gen_cni_anno_port_mappings_element (g, ptr->items[i], ctx, err);
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);


            }
      }
    stat = yajl_gen_array_close ((yajl_gen) g);


    if (ptr->len > 0 && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 1);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    return yajl_gen_status_ok;
}

cni_anno_port_mappings_container *
cni_anno_port_mappings_container_parse_file (const char *filename, const struct parser_context *ctx, parser_error *err)
{
cni_anno_port_mappings_container *ptr = NULL;size_t filesize;
    __auto_free char *content = NULL;

    if (filename == NULL || err == NULL)
      return NULL;

    *err = NULL;
    content = read_file (filename, &filesize);
    if (content == NULL)
      {
        if (asprintf (err, "cannot read the file: %s", filename) < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }ptr = cni_anno_port_mappings_container_parse_data (content, ctx, err);return ptr;
}
cni_anno_port_mappings_container * 
cni_anno_port_mappings_container_parse_file_stream (FILE *stream, const struct parser_context *ctx, parser_error *err)
{cni_anno_port_mappings_container *ptr = NULL;
size_t filesize;
    __auto_free char *content = NULL;

    if (stream == NULL || err == NULL)
      return NULL;

    *err = NULL;
    content = fread_file (stream, &filesize);
    if (content == NULL)
      {
        *err = strdup ("cannot read the file");
        return NULL;
      }
ptr = cni_anno_port_mappings_container_parse_data (content, ctx, err);return ptr;
}

define_cleaner_function (yajl_val, yajl_tree_free)

 cni_anno_port_mappings_container * cni_anno_port_mappings_container_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)
 { 
  cni_anno_port_mappings_container *ptr = NULL;__auto_cleanup(yajl_tree_free) yajl_val tree = NULL;
    char errbuf[1024];
    struct parser_context tmp_ctx = { 0 };

    if (jsondata == NULL || err == NULL)
      return NULL;

    *err = NULL;
    if (ctx == NULL)
     ctx = (const struct parser_context *)(&tmp_ctx);

    tree = yajl_tree_parse (jsondata, errbuf, sizeof (errbuf));
    if (tree == NULL)
      {
        if (asprintf (err, "cannot parse the data: %s", errbuf) < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }
ptr = make_cni_anno_port_mappings_container (tree, ctx, err);return ptr; 
}

static void
cleanup_yajl_gen (yajl_gen g)
{
    if (!g)
      return;
    yajl_gen_clear (g);
    yajl_gen_free (g);
}

define_cleaner_function (yajl_gen, cleanup_yajl_gen)


 char * 
cni_anno_port_mappings_container_generate_json (const cni_anno_port_mappings_container *ptr, const struct parser_context *ctx, parser_error *err){
    __auto_cleanup(cleanup_yajl_gen) yajl_gen g = NULL;
    struct parser_context tmp_ctx = { 0 };
    const unsigned char *gen_buf = NULL;
    char *json_buf = NULL;
    size_t gen_len = 0;

    if (ptr == NULL || err == NULL)
      return NULL;

    *err = NULL;
    if (ctx == NULL)
        ctx = (const struct parser_context *)(&tmp_ctx);

    if (!json_gen_init(&g, ctx))
      {
        *err = strdup ("Json_gen init failed");
        return json_buf;
      } 

if (yajl_gen_status_ok != gen_cni_anno_port_mappings_container (g, ptr, ctx, err))  {
        if (*err == NULL)
            *err = strdup ("Failed to generate json");
        return json_buf;
      }

    yajl_gen_get_buf (g, &gen_buf, &gen_len);
    if (gen_buf == NULL)
      {
        *err = strdup ("Error to get generated json");
        return json_buf;
      }

    json_buf = calloc (1, gen_len + 1);
    if (json_buf == NULL)
      {
        *err = strdup ("Cannot allocate memory");
        return json_buf;
      }
    (void) memcpy (json_buf, gen_buf, gen_len);
    json_buf[gen_len] = '\0';

    return json_buf;
}
