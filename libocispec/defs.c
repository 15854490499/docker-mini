/* Generated from defs.json. Do not edit!  */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include "read-file.h"
#include "defs.h"

#define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)
#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)
define_cleaner_function (defs_map_string_object_element *, free_defs_map_string_object_element)
defs_map_string_object_element *
make_defs_map_string_object_element (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_map_string_object_element) defs_map_string_object_element *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    return move_ptr (ret);
}

void
free_defs_map_string_object_element (defs_map_string_object_element *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr);
}

yajl_gen_status
gen_defs_map_string_object_element (yajl_gen g, const defs_map_string_object_element *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    if (!(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 0);
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    stat = yajl_gen_map_close ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if (!(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 1);
    return yajl_gen_status_ok;
}

define_cleaner_function (defs_map_string_object *, free_defs_map_string_object)
defs_map_string_object *
make_defs_map_string_object (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_map_string_object) defs_map_string_object *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    if (YAJL_GET_OBJECT (tree) != NULL)
      {
        size_t i;
        size_t len = YAJL_GET_OBJECT_NO_CHECK (tree)->len;
        const char **keys = YAJL_GET_OBJECT_NO_CHECK (tree)->keys;
        yajl_val *values = YAJL_GET_OBJECT_NO_CHECK (tree)->values;
        ret->len = len;
        ret->keys = calloc (len + 1, sizeof (*ret->keys));
        if (ret->keys == NULL)
          return NULL;
        ret->values = calloc (len + 1, sizeof (*ret->values));
        if (ret->values == NULL)
          return NULL;
        for (i = 0; i < len; i++)
          {
            yajl_val val;
            const char *tmpkey = keys[i];
            ret->keys[i] = strdup (tmpkey ? tmpkey : "");
            if (ret->keys[i] == NULL)
              return NULL;
            val = values[i];
            ret->values[i] = make_defs_map_string_object_element (val, ctx, err);
            if (ret->values[i] == NULL)
              return NULL;
          }
      }
    return move_ptr (ret);
}

void
free_defs_map_string_object (defs_map_string_object *ptr)
{
    if (ptr == NULL)
        return;
    if (ptr->keys != NULL && ptr->values != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->len; i++)
          {
            free (ptr->keys[i]);
            ptr->keys[i] = NULL;
            free_defs_map_string_object_element (ptr->values[i]);
            ptr->values[i] = NULL;
          }
        free (ptr->keys);
        ptr->keys = NULL;
        free (ptr->values);
        ptr->values = NULL;
      }
    free (ptr);
}

yajl_gen_status
gen_defs_map_string_object (yajl_gen g, const defs_map_string_object *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    size_t len = 0, i;
    if (ptr != NULL)
        len = ptr->len;
    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 0);
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if (len || (ptr != NULL && ptr->keys != NULL && ptr->values != NULL))
      {
        for (i = 0; i < len; i++)
          {
            char *str = ptr->keys[i] ? ptr->keys[i] : "";
            stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)str, strlen (str));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
            stat = gen_defs_map_string_object_element (g, ptr->values[i], ctx, err);
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
      }
    stat = yajl_gen_map_close ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 1);
    return yajl_gen_status_ok;
}

define_cleaner_function (defs_map_string_object_auths_element *, free_defs_map_string_object_auths_element)
defs_map_string_object_auths_element *
make_defs_map_string_object_auths_element (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_map_string_object_auths_element) defs_map_string_object_auths_element *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "auth", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->auth = strdup (str ? str : "");
            if (ret->auth == NULL)
              return NULL;
          }
      }
    while (0);

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
          {if (strcmp (tree->u.object.keys[i], "auth")){
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
free_defs_map_string_object_auths_element (defs_map_string_object_auths_element *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr->auth);
    ptr->auth = NULL;
    yajl_tree_free (ptr->_residual);
    ptr->_residual = NULL;
    free (ptr);
}

yajl_gen_status
gen_defs_map_string_object_auths_element (yajl_gen g, const defs_map_string_object_auths_element *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->auth != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("auth"), 4 /* strlen ("auth") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->auth != NULL)
            str = ptr->auth;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
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

define_cleaner_function (defs_map_string_object_auths *, free_defs_map_string_object_auths)
defs_map_string_object_auths *
make_defs_map_string_object_auths (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_map_string_object_auths) defs_map_string_object_auths *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    if (YAJL_GET_OBJECT (tree) != NULL)
      {
        size_t i;
        size_t len = YAJL_GET_OBJECT_NO_CHECK (tree)->len;
        const char **keys = YAJL_GET_OBJECT_NO_CHECK (tree)->keys;
        yajl_val *values = YAJL_GET_OBJECT_NO_CHECK (tree)->values;
        ret->len = len;
        ret->keys = calloc (len + 1, sizeof (*ret->keys));
        if (ret->keys == NULL)
          return NULL;
        ret->values = calloc (len + 1, sizeof (*ret->values));
        if (ret->values == NULL)
          return NULL;
        for (i = 0; i < len; i++)
          {
            yajl_val val;
            const char *tmpkey = keys[i];
            ret->keys[i] = strdup (tmpkey ? tmpkey : "");
            if (ret->keys[i] == NULL)
              return NULL;
            val = values[i];
            ret->values[i] = make_defs_map_string_object_auths_element (val, ctx, err);
            if (ret->values[i] == NULL)
              return NULL;
          }
      }
    return move_ptr (ret);
}

void
free_defs_map_string_object_auths (defs_map_string_object_auths *ptr)
{
    if (ptr == NULL)
        return;
    if (ptr->keys != NULL && ptr->values != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->len; i++)
          {
            free (ptr->keys[i]);
            ptr->keys[i] = NULL;
            free_defs_map_string_object_auths_element (ptr->values[i]);
            ptr->values[i] = NULL;
          }
        free (ptr->keys);
        ptr->keys = NULL;
        free (ptr->values);
        ptr->values = NULL;
      }
    free (ptr);
}

yajl_gen_status
gen_defs_map_string_object_auths (yajl_gen g, const defs_map_string_object_auths *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    size_t len = 0, i;
    if (ptr != NULL)
        len = ptr->len;
    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 0);
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if (len || (ptr != NULL && ptr->keys != NULL && ptr->values != NULL))
      {
        for (i = 0; i < len; i++)
          {
            char *str = ptr->keys[i] ? ptr->keys[i] : "";
            stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)str, strlen (str));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
            stat = gen_defs_map_string_object_auths_element (g, ptr->values[i], ctx, err);
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
      }
    stat = yajl_gen_map_close ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 1);
    return yajl_gen_status_ok;
}

define_cleaner_function (defs_map_string_object_port_bindings_element *, free_defs_map_string_object_port_bindings_element)
defs_map_string_object_port_bindings_element *
make_defs_map_string_object_port_bindings_element (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_map_string_object_port_bindings_element) defs_map_string_object_port_bindings_element *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    ret->element = make_network_port_binding (get_val (tree, "Element", yajl_t_object), ctx, err);
    if (ret->element == NULL && *err != 0)
      return NULL;

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
          {if (strcmp (tree->u.object.keys[i], "Element")){
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
free_defs_map_string_object_port_bindings_element (defs_map_string_object_port_bindings_element *ptr)
{
    if (ptr == NULL)
        return;
    if (ptr->element != NULL)
      {
        free_network_port_binding (ptr->element);
        ptr->element = NULL;
      }
    yajl_tree_free (ptr->_residual);
    ptr->_residual = NULL;
    free (ptr);
}

yajl_gen_status
gen_defs_map_string_object_port_bindings_element (yajl_gen g, const defs_map_string_object_port_bindings_element *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->element != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Element"), 7 /* strlen ("Element") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_network_port_binding (g, ptr != NULL ? ptr->element : NULL, ctx, err);
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

define_cleaner_function (defs_map_string_object_port_bindings *, free_defs_map_string_object_port_bindings)
defs_map_string_object_port_bindings *
make_defs_map_string_object_port_bindings (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_map_string_object_port_bindings) defs_map_string_object_port_bindings *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    if (YAJL_GET_OBJECT (tree) != NULL)
      {
        size_t i;
        size_t len = YAJL_GET_OBJECT_NO_CHECK (tree)->len;
        const char **keys = YAJL_GET_OBJECT_NO_CHECK (tree)->keys;
        yajl_val *values = YAJL_GET_OBJECT_NO_CHECK (tree)->values;
        ret->len = len;
        ret->keys = calloc (len + 1, sizeof (*ret->keys));
        if (ret->keys == NULL)
          return NULL;
        ret->values = calloc (len + 1, sizeof (*ret->values));
        if (ret->values == NULL)
          return NULL;
        for (i = 0; i < len; i++)
          {
            yajl_val val;
            const char *tmpkey = keys[i];
            ret->keys[i] = strdup (tmpkey ? tmpkey : "");
            if (ret->keys[i] == NULL)
              return NULL;
            val = values[i];
            ret->values[i] = make_defs_map_string_object_port_bindings_element (val, ctx, err);
            if (ret->values[i] == NULL)
              return NULL;
          }
      }
    return move_ptr (ret);
}

void
free_defs_map_string_object_port_bindings (defs_map_string_object_port_bindings *ptr)
{
    if (ptr == NULL)
        return;
    if (ptr->keys != NULL && ptr->values != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->len; i++)
          {
            free (ptr->keys[i]);
            ptr->keys[i] = NULL;
            free_defs_map_string_object_port_bindings_element (ptr->values[i]);
            ptr->values[i] = NULL;
          }
        free (ptr->keys);
        ptr->keys = NULL;
        free (ptr->values);
        ptr->values = NULL;
      }
    free (ptr);
}

yajl_gen_status
gen_defs_map_string_object_port_bindings (yajl_gen g, const defs_map_string_object_port_bindings *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    size_t len = 0, i;
    if (ptr != NULL)
        len = ptr->len;
    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 0);
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if (len || (ptr != NULL && ptr->keys != NULL && ptr->values != NULL))
      {
        for (i = 0; i < len; i++)
          {
            char *str = ptr->keys[i] ? ptr->keys[i] : "";
            stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)str, strlen (str));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
            stat = gen_defs_map_string_object_port_bindings_element (g, ptr->values[i], ctx, err);
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
      }
    stat = yajl_gen_map_close ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 1);
    return yajl_gen_status_ok;
}

define_cleaner_function (defs_map_string_object_networks_element *, free_defs_map_string_object_networks_element)
defs_map_string_object_networks_element *
make_defs_map_string_object_networks_element (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_map_string_object_networks_element) defs_map_string_object_networks_element *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val tmp = get_val (tree, "Links", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->links_len = len;
            ret->links = calloc (len + 1, sizeof (*ret->links));
            if (ret->links == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                if (val != NULL)
                  {
                    char *str = YAJL_GET_STRING (val);
                    ret->links[i] = strdup (str ? str : "");
                    if (ret->links[i] == NULL)
                      return NULL;
                  }
              }
        }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "Alias", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->alias_len = len;
            ret->alias = calloc (len + 1, sizeof (*ret->alias));
            if (ret->alias == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                if (val != NULL)
                  {
                    char *str = YAJL_GET_STRING (val);
                    ret->alias[i] = strdup (str ? str : "");
                    if (ret->alias[i] == NULL)
                      return NULL;
                  }
              }
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "NetworkID", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->network_id = strdup (str ? str : "");
            if (ret->network_id == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "EndpointID", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->endpoint_id = strdup (str ? str : "");
            if (ret->endpoint_id == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "Gateway", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->gateway = strdup (str ? str : "");
            if (ret->gateway == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "IPAddress", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->ip_address = strdup (str ? str : "");
            if (ret->ip_address == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "IPPrefixLen", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int (YAJL_GET_NUMBER (val), (int *)&ret->ip_prefix_len);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'integer' for key 'IPPrefixLen': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->ip_prefix_len_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "IPv6Gateway", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->i_pv6gateway = strdup (str ? str : "");
            if (ret->i_pv6gateway == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "GlobalIPv6Address", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->global_i_pv6address = strdup (str ? str : "");
            if (ret->global_i_pv6address == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "GlobalIPv6PrefixLen", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int (YAJL_GET_NUMBER (val), (int *)&ret->global_i_pv6prefix_len);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'integer' for key 'GlobalIPv6PrefixLen': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->global_i_pv6prefix_len_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "MacAddress", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->mac_address = strdup (str ? str : "");
            if (ret->mac_address == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "IFName", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->if_name = strdup (str ? str : "");
            if (ret->if_name == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "DriverOpts", yajl_t_object);
        if (tmp != NULL)
          {
            ret->driver_opts = make_json_map_string_string (tmp, ctx, err);
            if (ret->driver_opts == NULL)
              {
                char *new_error = NULL;
                if (asprintf (&new_error, "Value error for key 'DriverOpts': %s", *err ? *err : "null") < 0)
                  new_error = strdup ("error allocating memory");
                free (*err);
                *err = new_error;
                return NULL;
              }
          }
      }
    while (0);

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
          {if (strcmp (tree->u.object.keys[i], "Links")
                && strcmp (tree->u.object.keys[i], "Alias")
                && strcmp (tree->u.object.keys[i], "NetworkID")
                && strcmp (tree->u.object.keys[i], "EndpointID")
                && strcmp (tree->u.object.keys[i], "Gateway")
                && strcmp (tree->u.object.keys[i], "IPAddress")
                && strcmp (tree->u.object.keys[i], "IPPrefixLen")
                && strcmp (tree->u.object.keys[i], "IPv6Gateway")
                && strcmp (tree->u.object.keys[i], "GlobalIPv6Address")
                && strcmp (tree->u.object.keys[i], "GlobalIPv6PrefixLen")
                && strcmp (tree->u.object.keys[i], "MacAddress")
                && strcmp (tree->u.object.keys[i], "IFName")
                && strcmp (tree->u.object.keys[i], "DriverOpts")){
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
free_defs_map_string_object_networks_element (defs_map_string_object_networks_element *ptr)
{
    if (ptr == NULL)
        return;
    if (ptr->links != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->links_len; i++)
          {
            if (ptr->links[i] != NULL)
              {
                free (ptr->links[i]);
                ptr->links[i] = NULL;
              }
          }
        free (ptr->links);
        ptr->links = NULL;
    }
    if (ptr->alias != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->alias_len; i++)
          {
            if (ptr->alias[i] != NULL)
              {
                free (ptr->alias[i]);
                ptr->alias[i] = NULL;
              }
          }
        free (ptr->alias);
        ptr->alias = NULL;
    }
    free (ptr->network_id);
    ptr->network_id = NULL;
    free (ptr->endpoint_id);
    ptr->endpoint_id = NULL;
    free (ptr->gateway);
    ptr->gateway = NULL;
    free (ptr->ip_address);
    ptr->ip_address = NULL;
    free (ptr->i_pv6gateway);
    ptr->i_pv6gateway = NULL;
    free (ptr->global_i_pv6address);
    ptr->global_i_pv6address = NULL;
    free (ptr->mac_address);
    ptr->mac_address = NULL;
    free (ptr->if_name);
    ptr->if_name = NULL;
    free_json_map_string_string (ptr->driver_opts);
    ptr->driver_opts = NULL;
    yajl_tree_free (ptr->_residual);
    ptr->_residual = NULL;
    free (ptr);
}

yajl_gen_status
gen_defs_map_string_object_networks_element (yajl_gen g, const defs_map_string_object_networks_element *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->links != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Links"), 5 /* strlen ("Links") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->links != NULL)
          len = ptr->links_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(ptr->links[i]), strlen (ptr->links[i]));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->alias != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Alias"), 5 /* strlen ("Alias") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->alias != NULL)
          len = ptr->alias_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(ptr->alias[i]), strlen (ptr->alias[i]));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->network_id != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("NetworkID"), 9 /* strlen ("NetworkID") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->network_id != NULL)
            str = ptr->network_id;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->endpoint_id != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("EndpointID"), 10 /* strlen ("EndpointID") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->endpoint_id != NULL)
            str = ptr->endpoint_id;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->gateway != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Gateway"), 7 /* strlen ("Gateway") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->gateway != NULL)
            str = ptr->gateway;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->ip_address != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("IPAddress"), 9 /* strlen ("IPAddress") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->ip_address != NULL)
            str = ptr->ip_address;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->ip_prefix_len_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("IPPrefixLen"), 11 /* strlen ("IPPrefixLen") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->ip_prefix_len)
            num = (long long int)ptr->ip_prefix_len;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->i_pv6gateway != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("IPv6Gateway"), 11 /* strlen ("IPv6Gateway") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->i_pv6gateway != NULL)
            str = ptr->i_pv6gateway;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->global_i_pv6address != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("GlobalIPv6Address"), 17 /* strlen ("GlobalIPv6Address") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->global_i_pv6address != NULL)
            str = ptr->global_i_pv6address;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->global_i_pv6prefix_len_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("GlobalIPv6PrefixLen"), 19 /* strlen ("GlobalIPv6PrefixLen") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->global_i_pv6prefix_len)
            num = (long long int)ptr->global_i_pv6prefix_len;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->mac_address != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("MacAddress"), 10 /* strlen ("MacAddress") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->mac_address != NULL)
            str = ptr->mac_address;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->if_name != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("IFName"), 6 /* strlen ("IFName") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->if_name != NULL)
            str = ptr->if_name;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->driver_opts != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("driver_opts"), 10 /* strlen ("driver_opts") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_json_map_string_string (g, ptr ? ptr->driver_opts : NULL, ctx, err);
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

define_cleaner_function (defs_map_string_object_networks *, free_defs_map_string_object_networks)
defs_map_string_object_networks *
make_defs_map_string_object_networks (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_map_string_object_networks) defs_map_string_object_networks *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    if (YAJL_GET_OBJECT (tree) != NULL)
      {
        size_t i;
        size_t len = YAJL_GET_OBJECT_NO_CHECK (tree)->len;
        const char **keys = YAJL_GET_OBJECT_NO_CHECK (tree)->keys;
        yajl_val *values = YAJL_GET_OBJECT_NO_CHECK (tree)->values;
        ret->len = len;
        ret->keys = calloc (len + 1, sizeof (*ret->keys));
        if (ret->keys == NULL)
          return NULL;
        ret->values = calloc (len + 1, sizeof (*ret->values));
        if (ret->values == NULL)
          return NULL;
        for (i = 0; i < len; i++)
          {
            yajl_val val;
            const char *tmpkey = keys[i];
            ret->keys[i] = strdup (tmpkey ? tmpkey : "");
            if (ret->keys[i] == NULL)
              return NULL;
            val = values[i];
            ret->values[i] = make_defs_map_string_object_networks_element (val, ctx, err);
            if (ret->values[i] == NULL)
              return NULL;
          }
      }
    return move_ptr (ret);
}

void
free_defs_map_string_object_networks (defs_map_string_object_networks *ptr)
{
    if (ptr == NULL)
        return;
    if (ptr->keys != NULL && ptr->values != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->len; i++)
          {
            free (ptr->keys[i]);
            ptr->keys[i] = NULL;
            free_defs_map_string_object_networks_element (ptr->values[i]);
            ptr->values[i] = NULL;
          }
        free (ptr->keys);
        ptr->keys = NULL;
        free (ptr->values);
        ptr->values = NULL;
      }
    free (ptr);
}

yajl_gen_status
gen_defs_map_string_object_networks (yajl_gen g, const defs_map_string_object_networks *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    size_t len = 0, i;
    if (ptr != NULL)
        len = ptr->len;
    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 0);
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if (len || (ptr != NULL && ptr->keys != NULL && ptr->values != NULL))
      {
        for (i = 0; i < len; i++)
          {
            char *str = ptr->keys[i] ? ptr->keys[i] : "";
            stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)str, strlen (str));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
            stat = gen_defs_map_string_object_networks_element (g, ptr->values[i], ctx, err);
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
      }
    stat = yajl_gen_map_close ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
        yajl_gen_config (g, yajl_gen_beautify, 1);
    return yajl_gen_status_ok;
}

define_cleaner_function (defs_health_check *, free_defs_health_check)
defs_health_check *
make_defs_health_check (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_health_check) defs_health_check *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val tmp = get_val (tree, "Test", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->test_len = len;
            ret->test = calloc (len + 1, sizeof (*ret->test));
            if (ret->test == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                if (val != NULL)
                  {
                    char *str = YAJL_GET_STRING (val);
                    ret->test[i] = strdup (str ? str : "");
                    if (ret->test[i] == NULL)
                      return NULL;
                  }
              }
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "Interval", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int64 (YAJL_GET_NUMBER (val), &ret->interval);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'int64' for key 'Interval': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->interval_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "Timeout", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int64 (YAJL_GET_NUMBER (val), &ret->timeout);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'int64' for key 'Timeout': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->timeout_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "StartPeriod", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int64 (YAJL_GET_NUMBER (val), &ret->start_period);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'int64' for key 'StartPeriod': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->start_period_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "Retries", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int (YAJL_GET_NUMBER (val), (int *)&ret->retries);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'integer' for key 'Retries': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->retries_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "ExitOnUnhealthy", yajl_t_true);
        if (val != NULL)
          {
            ret->exit_on_unhealthy = YAJL_IS_TRUE(val);
            ret->exit_on_unhealthy_present = 1;
          }
        else
          {
            val = get_val (tree, "ExitOnUnhealthy", yajl_t_false);
            if (val != NULL)
              {
                ret->exit_on_unhealthy = 0;
                ret->exit_on_unhealthy_present = 1;
              }
          }
      }
    while (0);

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
          {if (strcmp (tree->u.object.keys[i], "Test")
                && strcmp (tree->u.object.keys[i], "Interval")
                && strcmp (tree->u.object.keys[i], "Timeout")
                && strcmp (tree->u.object.keys[i], "StartPeriod")
                && strcmp (tree->u.object.keys[i], "Retries")
                && strcmp (tree->u.object.keys[i], "ExitOnUnhealthy")){
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
free_defs_health_check (defs_health_check *ptr)
{
    if (ptr == NULL)
        return;
    if (ptr->test != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->test_len; i++)
          {
            if (ptr->test[i] != NULL)
              {
                free (ptr->test[i]);
                ptr->test[i] = NULL;
              }
          }
        free (ptr->test);
        ptr->test = NULL;
    }
    yajl_tree_free (ptr->_residual);
    ptr->_residual = NULL;
    free (ptr);
}

yajl_gen_status
gen_defs_health_check (yajl_gen g, const defs_health_check *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->test != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Test"), 4 /* strlen ("Test") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->test != NULL)
          len = ptr->test_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(ptr->test[i]), strlen (ptr->test[i]));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->interval_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Interval"), 8 /* strlen ("Interval") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->interval)
            num = (long long int)ptr->interval;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->timeout_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Timeout"), 7 /* strlen ("Timeout") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->timeout)
            num = (long long int)ptr->timeout;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->start_period_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("StartPeriod"), 11 /* strlen ("StartPeriod") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->start_period)
            num = (long long int)ptr->start_period;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->retries_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Retries"), 7 /* strlen ("Retries") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->retries)
            num = (long long int)ptr->retries;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->exit_on_unhealthy_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("ExitOnUnhealthy"), 15 /* strlen ("ExitOnUnhealthy") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->exit_on_unhealthy)
            b = ptr->exit_on_unhealthy;
        
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

define_cleaner_function (defs_health_log_element *, free_defs_health_log_element)
defs_health_log_element *
make_defs_health_log_element (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_health_log_element) defs_health_log_element *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "Start", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->start = strdup (str ? str : "");
            if (ret->start == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "End", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->end = strdup (str ? str : "");
            if (ret->end == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "ExitCode", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int (YAJL_GET_NUMBER (val), (int *)&ret->exit_code);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'integer' for key 'ExitCode': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->exit_code_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "Output", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->output = strdup (str ? str : "");
            if (ret->output == NULL)
              return NULL;
          }
      }
    while (0);
    return move_ptr (ret);
}

void
free_defs_health_log_element (defs_health_log_element *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr->start);
    ptr->start = NULL;
    free (ptr->end);
    ptr->end = NULL;
    free (ptr->output);
    ptr->output = NULL;
    free (ptr);
}

yajl_gen_status
gen_defs_health_log_element (yajl_gen g, const defs_health_log_element *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->start != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Start"), 5 /* strlen ("Start") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->start != NULL)
            str = ptr->start;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->end != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("End"), 3 /* strlen ("End") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->end != NULL)
            str = ptr->end;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->exit_code_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("ExitCode"), 8 /* strlen ("ExitCode") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->exit_code)
            num = (long long int)ptr->exit_code;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->output != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Output"), 6 /* strlen ("Output") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->output != NULL)
            str = ptr->output;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    stat = yajl_gen_map_close ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    return yajl_gen_status_ok;
}

define_cleaner_function (defs_health *, free_defs_health)
defs_health *
make_defs_health (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_defs_health) defs_health *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "Status", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->status = strdup (str ? str : "");
            if (ret->status == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "FailingStreak", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int (YAJL_GET_NUMBER (val), (int *)&ret->failing_streak);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'integer' for key 'FailingStreak': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->failing_streak_present = 1;
        }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "Log", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->log_len = len;
            ret->log = calloc (len + 1, sizeof (*ret->log));
            if (ret->log == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                ret->log[i] = make_defs_health_log_element (val, ctx, err);
                if (ret->log[i] == NULL)
                  return NULL;
              }
          }
      }
    while (0);

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
          {if (strcmp (tree->u.object.keys[i], "Status")
                && strcmp (tree->u.object.keys[i], "FailingStreak")
                && strcmp (tree->u.object.keys[i], "Log")){
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
free_defs_health (defs_health *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr->status);
    ptr->status = NULL;
    if (ptr->log != NULL)      {
        size_t i;
        for (i = 0; i < ptr->log_len; i++)
          {
          if (ptr->log[i] != NULL)
            {
              free_defs_health_log_element (ptr->log[i]);
              ptr->log[i] = NULL;
            }
          }
        free (ptr->log);
        ptr->log = NULL;
      }
    yajl_tree_free (ptr->_residual);
    ptr->_residual = NULL;
    free (ptr);
}

yajl_gen_status
gen_defs_health (yajl_gen g, const defs_health *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->status != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Status"), 6 /* strlen ("Status") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->status != NULL)
            str = ptr->status;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->failing_streak_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("FailingStreak"), 13 /* strlen ("FailingStreak") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->failing_streak)
            num = (long long int)ptr->failing_streak;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->log != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Log"), 3 /* strlen ("Log") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->log != NULL)
            len = ptr->log_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = gen_defs_health_log_element (g, ptr->log[i], ctx, err);
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
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

