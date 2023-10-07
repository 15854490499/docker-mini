/* Generated from defs.json. Do not edit!  */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include "read-file.h"
#include "image_spec_schema_defs.h"

#define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)
#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)
define_cleaner_function (image_spec_schema_defs_map_string_object_element *, free_image_spec_schema_defs_map_string_object_element)
image_spec_schema_defs_map_string_object_element *
make_image_spec_schema_defs_map_string_object_element (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_image_spec_schema_defs_map_string_object_element) image_spec_schema_defs_map_string_object_element *ret = NULL;
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
free_image_spec_schema_defs_map_string_object_element (image_spec_schema_defs_map_string_object_element *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr);
}

yajl_gen_status
gen_image_spec_schema_defs_map_string_object_element (yajl_gen g, const image_spec_schema_defs_map_string_object_element *ptr, const struct parser_context *ctx, parser_error *err)
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

define_cleaner_function (image_spec_schema_defs_map_string_object *, free_image_spec_schema_defs_map_string_object)
image_spec_schema_defs_map_string_object *
make_image_spec_schema_defs_map_string_object (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_image_spec_schema_defs_map_string_object) image_spec_schema_defs_map_string_object *ret = NULL;
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
            ret->values[i] = make_image_spec_schema_defs_map_string_object_element (val, ctx, err);
            if (ret->values[i] == NULL)
              return NULL;
          }
      }
    return move_ptr (ret);
}

void
free_image_spec_schema_defs_map_string_object (image_spec_schema_defs_map_string_object *ptr)
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
            free_image_spec_schema_defs_map_string_object_element (ptr->values[i]);
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
gen_image_spec_schema_defs_map_string_object (yajl_gen g, const image_spec_schema_defs_map_string_object *ptr, const struct parser_context *ctx, parser_error *err)
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
            stat = gen_image_spec_schema_defs_map_string_object_element (g, ptr->values[i], ctx, err);
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

define_cleaner_function (image_spec_schema_defs_map_string_object_auths_element *, free_image_spec_schema_defs_map_string_object_auths_element)
image_spec_schema_defs_map_string_object_auths_element *
make_image_spec_schema_defs_map_string_object_auths_element (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_image_spec_schema_defs_map_string_object_auths_element) image_spec_schema_defs_map_string_object_auths_element *ret = NULL;
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
free_image_spec_schema_defs_map_string_object_auths_element (image_spec_schema_defs_map_string_object_auths_element *ptr)
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
gen_image_spec_schema_defs_map_string_object_auths_element (yajl_gen g, const image_spec_schema_defs_map_string_object_auths_element *ptr, const struct parser_context *ctx, parser_error *err)
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

define_cleaner_function (image_spec_schema_defs_map_string_object_auths *, free_image_spec_schema_defs_map_string_object_auths)
image_spec_schema_defs_map_string_object_auths *
make_image_spec_schema_defs_map_string_object_auths (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_image_spec_schema_defs_map_string_object_auths) image_spec_schema_defs_map_string_object_auths *ret = NULL;
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
            ret->values[i] = make_image_spec_schema_defs_map_string_object_auths_element (val, ctx, err);
            if (ret->values[i] == NULL)
              return NULL;
          }
      }
    return move_ptr (ret);
}

void
free_image_spec_schema_defs_map_string_object_auths (image_spec_schema_defs_map_string_object_auths *ptr)
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
            free_image_spec_schema_defs_map_string_object_auths_element (ptr->values[i]);
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
gen_image_spec_schema_defs_map_string_object_auths (yajl_gen g, const image_spec_schema_defs_map_string_object_auths *ptr, const struct parser_context *ctx, parser_error *err)
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
            stat = gen_image_spec_schema_defs_map_string_object_auths_element (g, ptr->values[i], ctx, err);
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

define_cleaner_function (image_spec_schema_defs_health_check *, free_image_spec_schema_defs_health_check)
image_spec_schema_defs_health_check *
make_image_spec_schema_defs_health_check (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_image_spec_schema_defs_health_check) image_spec_schema_defs_health_check *ret = NULL;
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
free_image_spec_schema_defs_health_check (image_spec_schema_defs_health_check *ptr)
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
gen_image_spec_schema_defs_health_check (yajl_gen g, const image_spec_schema_defs_health_check *ptr, const struct parser_context *ctx, parser_error *err)
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

