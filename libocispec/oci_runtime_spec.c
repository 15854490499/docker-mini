/* Generated from spec.json. Do not edit!  */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include "read-file.h"
#include "oci_runtime_spec.h"

#define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)
#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)
define_cleaner_function (oci_runtime_spec_root *, free_oci_runtime_spec_root)
oci_runtime_spec_root *
make_oci_runtime_spec_root (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_oci_runtime_spec_root) oci_runtime_spec_root *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "path", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->path = strdup (str ? str : "");
            if (ret->path == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "readonly", yajl_t_true);
        if (val != NULL)
          {
            ret->readonly = YAJL_IS_TRUE(val);
            ret->readonly_present = 1;
          }
        else
          {
            val = get_val (tree, "readonly", yajl_t_false);
            if (val != NULL)
              {
                ret->readonly = 0;
                ret->readonly_present = 1;
              }
          }
      }
    while (0);
    if (ret->path == NULL)
      {
        if (asprintf (err, "Required field '%s' not present",  "path") < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }

    if (tree->type == yajl_t_object)
      {
        size_t i;
        size_t j = 0;
        size_t cnt = tree->u.object.len;
        yajl_val resi = NULL;

        if (ctx->options & OPT_PARSE_FULLKEY)
          {
            resi = calloc (1, sizeof(*tree));
            if (resi == NULL)
              return NULL;

            resi->type = yajl_t_object;
            resi->u.object.keys = calloc (cnt, sizeof (const char *));
            if (resi->u.object.keys == NULL)
              {
                yajl_tree_free (resi);
                return NULL;
              }
            resi->u.object.values = calloc (cnt, sizeof (yajl_val));
            if (resi->u.object.values == NULL)
              {
                yajl_tree_free (resi);
                return NULL;
              }
          }

        for (i = 0; i < tree->u.object.len; i++)
          {if (strcmp (tree->u.object.keys[i], "path")
                && strcmp (tree->u.object.keys[i], "readonly")){
                if (ctx->options & OPT_PARSE_FULLKEY)
                  {
                    resi->u.object.keys[j] = tree->u.object.keys[i];
                    tree->u.object.keys[i] = NULL;
                    resi->u.object.values[j] = tree->u.object.values[i];
                    tree->u.object.values[i] = NULL;
                    resi->u.object.len++;
                  }
                j++;
              }
          }
        if (ctx->options & OPT_PARSE_STRICT)
          {
            if (j > 0 && ctx->errfile != NULL)
                (void) fprintf (ctx->errfile, "WARNING: unknown key found\n");
          }
        if (ctx->options & OPT_PARSE_FULLKEY)
            ret->_residual = resi;
      }
    return move_ptr (ret);
}

void
free_oci_runtime_spec_root (oci_runtime_spec_root *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr->path);
    ptr->path = NULL;
    yajl_tree_free (ptr->_residual);
    ptr->_residual = NULL;
    free (ptr);
}

yajl_gen_status
gen_oci_runtime_spec_root (yajl_gen g, const oci_runtime_spec_root *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->path != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("path"), 4 /* strlen ("path") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->path != NULL)
            str = ptr->path;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->readonly_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("readonly"), 8 /* strlen ("readonly") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->readonly)
            b = ptr->readonly;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if (ptr != NULL && ptr->_residual != NULL)
      {
        stat = gen_yajl_object_residual (ptr->_residual, g, err);
        if (yajl_gen_status_ok != stat)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    stat = yajl_gen_map_close ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    return yajl_gen_status_ok;
}

define_cleaner_function (oci_runtime_spec *, free_oci_runtime_spec)
oci_runtime_spec *
make_oci_runtime_spec (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_oci_runtime_spec) oci_runtime_spec *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "ociVersion", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->oci_version = strdup (str ? str : "");
            if (ret->oci_version == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "hostname", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->hostname = strdup (str ? str : "");
            if (ret->hostname == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "mounts", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->mounts_len = len;
            ret->mounts = calloc (len + 1, sizeof (*ret->mounts));
            if (ret->mounts == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                ret->mounts[i] = make_oci_runtime_defs_mount (val, ctx, err);
                if (ret->mounts[i] == NULL)
                  return NULL;
              }
          }
      }
    while (0);
    ret->root = make_oci_runtime_spec_root (get_val (tree, "root", yajl_t_object), ctx, err);
    if (ret->root == NULL && *err != 0)
      return NULL;
    ret->linux = make_oci_runtime_config_linux (get_val (tree, "linux", yajl_t_object), ctx, err);
    if (ret->linux == NULL && *err != 0)
      return NULL;
    if (ret->oci_version == NULL)
      {
        if (asprintf (err, "Required field '%s' not present",  "ociVersion") < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }

    if (tree->type == yajl_t_object)
      {
        size_t i;
        size_t j = 0;
        size_t cnt = tree->u.object.len;
        yajl_val resi = NULL;

        if (ctx->options & OPT_PARSE_FULLKEY)
          {
            resi = calloc (1, sizeof(*tree));
            if (resi == NULL)
              return NULL;

            resi->type = yajl_t_object;
            resi->u.object.keys = calloc (cnt, sizeof (const char *));
            if (resi->u.object.keys == NULL)
              {
                yajl_tree_free (resi);
                return NULL;
              }
            resi->u.object.values = calloc (cnt, sizeof (yajl_val));
            if (resi->u.object.values == NULL)
              {
                yajl_tree_free (resi);
                return NULL;
              }
          }

        for (i = 0; i < tree->u.object.len; i++)
          {if (strcmp (tree->u.object.keys[i], "ociVersion")
                && strcmp (tree->u.object.keys[i], "hostname")
                && strcmp (tree->u.object.keys[i], "mounts")
                && strcmp (tree->u.object.keys[i], "root")
                && strcmp (tree->u.object.keys[i], "linux")){
                if (ctx->options & OPT_PARSE_FULLKEY)
                  {
                    resi->u.object.keys[j] = tree->u.object.keys[i];
                    tree->u.object.keys[i] = NULL;
                    resi->u.object.values[j] = tree->u.object.values[i];
                    tree->u.object.values[i] = NULL;
                    resi->u.object.len++;
                  }
                j++;
              }
          }
        if (ctx->options & OPT_PARSE_STRICT)
          {
            if (j > 0 && ctx->errfile != NULL)
                (void) fprintf (ctx->errfile, "WARNING: unknown key found\n");
          }
        if (ctx->options & OPT_PARSE_FULLKEY)
            ret->_residual = resi;
      }
    return move_ptr (ret);
}

void
free_oci_runtime_spec (oci_runtime_spec *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr->oci_version);
    ptr->oci_version = NULL;
    free (ptr->hostname);
    ptr->hostname = NULL;
    if (ptr->mounts != NULL)      {
        size_t i;
        for (i = 0; i < ptr->mounts_len; i++)
          {
          if (ptr->mounts[i] != NULL)
            {
              free_oci_runtime_defs_mount (ptr->mounts[i]);
              ptr->mounts[i] = NULL;
            }
          }
        free (ptr->mounts);
        ptr->mounts = NULL;
      }
    if (ptr->root != NULL)
      {
        free_oci_runtime_spec_root (ptr->root);
        ptr->root = NULL;
      }
    if (ptr->linux != NULL)
      {
        free_oci_runtime_config_linux (ptr->linux);
        ptr->linux = NULL;
      }
    yajl_tree_free (ptr->_residual);
    ptr->_residual = NULL;
    free (ptr);
}

yajl_gen_status
gen_oci_runtime_spec (yajl_gen g, const oci_runtime_spec *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->oci_version != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("ociVersion"), 10 /* strlen ("ociVersion") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->oci_version != NULL)
            str = ptr->oci_version;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->hostname != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("hostname"), 8 /* strlen ("hostname") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->hostname != NULL)
            str = ptr->hostname;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->mounts != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("mounts"), 6 /* strlen ("mounts") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->mounts != NULL)
            len = ptr->mounts_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = gen_oci_runtime_defs_mount (g, ptr->mounts[i], ctx, err);
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->root != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("root"), 4 /* strlen ("root") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_oci_runtime_spec_root (g, ptr != NULL ? ptr->root : NULL, ctx, err);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->linux != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("linux"), 5 /* strlen ("linux") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_oci_runtime_config_linux (g, ptr != NULL ? ptr->linux : NULL, ctx, err);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if (ptr != NULL && ptr->_residual != NULL)
      {
        stat = gen_yajl_object_residual (ptr->_residual, g, err);
        if (yajl_gen_status_ok != stat)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    stat = yajl_gen_map_close ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    return yajl_gen_status_ok;
}


oci_runtime_spec *
oci_runtime_spec_parse_file (const char *filename, const struct parser_context *ctx, parser_error *err)
{
oci_runtime_spec *ptr = NULL;size_t filesize;
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
      }ptr = oci_runtime_spec_parse_data (content, ctx, err);return ptr;
}
oci_runtime_spec * 
oci_runtime_spec_parse_file_stream (FILE *stream, const struct parser_context *ctx, parser_error *err)
{oci_runtime_spec *ptr = NULL;
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
ptr = oci_runtime_spec_parse_data (content, ctx, err);return ptr;
}

define_cleaner_function (yajl_val, yajl_tree_free)

 oci_runtime_spec * oci_runtime_spec_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)
 { 
  oci_runtime_spec *ptr = NULL;__auto_cleanup(yajl_tree_free) yajl_val tree = NULL;
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
ptr = make_oci_runtime_spec (tree, ctx, err);return ptr; 
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
oci_runtime_spec_generate_json (const oci_runtime_spec *ptr, const struct parser_context *ctx, parser_error *err){
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
if (yajl_gen_status_ok != gen_oci_runtime_spec (g, ptr, ctx, err))  {
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
