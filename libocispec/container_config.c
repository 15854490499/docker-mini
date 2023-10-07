/* Generated from config.json. Do not edit!  */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include "read-file.h"
#include "container_config.h"

#define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)
#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)
define_cleaner_function (container_config *, free_container_config)
container_config *
make_container_config (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_container_config) container_config *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "Hostname", yajl_t_string);
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
        yajl_val val = get_val (tree, "Domainname", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->domainname = strdup (str ? str : "");
            if (ret->domainname == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "User", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->user = strdup (str ? str : "");
            if (ret->user == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "AttachStdin", yajl_t_true);
        if (val != NULL)
          {
            ret->attach_stdin = YAJL_IS_TRUE(val);
            ret->attach_stdin_present = 1;
          }
        else
          {
            val = get_val (tree, "AttachStdin", yajl_t_false);
            if (val != NULL)
              {
                ret->attach_stdin = 0;
                ret->attach_stdin_present = 1;
              }
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "AttachStdout", yajl_t_true);
        if (val != NULL)
          {
            ret->attach_stdout = YAJL_IS_TRUE(val);
            ret->attach_stdout_present = 1;
          }
        else
          {
            val = get_val (tree, "AttachStdout", yajl_t_false);
            if (val != NULL)
              {
                ret->attach_stdout = 0;
                ret->attach_stdout_present = 1;
              }
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "AttachStderr", yajl_t_true);
        if (val != NULL)
          {
            ret->attach_stderr = YAJL_IS_TRUE(val);
            ret->attach_stderr_present = 1;
          }
        else
          {
            val = get_val (tree, "AttachStderr", yajl_t_false);
            if (val != NULL)
              {
                ret->attach_stderr = 0;
                ret->attach_stderr_present = 1;
              }
          }
      }
    while (0);
    ret->exposed_ports = make_defs_map_string_object (get_val (tree, "ExposedPorts", yajl_t_object), ctx, err);
    if (ret->exposed_ports == NULL && *err != 0)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "PublishService", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->publish_service = strdup (str ? str : "");
            if (ret->publish_service == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "Tty", yajl_t_true);
        if (val != NULL)
          {
            ret->tty = YAJL_IS_TRUE(val);
            ret->tty_present = 1;
          }
        else
          {
            val = get_val (tree, "Tty", yajl_t_false);
            if (val != NULL)
              {
                ret->tty = 0;
                ret->tty_present = 1;
              }
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "OpenStdin", yajl_t_true);
        if (val != NULL)
          {
            ret->open_stdin = YAJL_IS_TRUE(val);
            ret->open_stdin_present = 1;
          }
        else
          {
            val = get_val (tree, "OpenStdin", yajl_t_false);
            if (val != NULL)
              {
                ret->open_stdin = 0;
                ret->open_stdin_present = 1;
              }
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "StdinOnce", yajl_t_true);
        if (val != NULL)
          {
            ret->stdin_once = YAJL_IS_TRUE(val);
            ret->stdin_once_present = 1;
          }
        else
          {
            val = get_val (tree, "StdinOnce", yajl_t_false);
            if (val != NULL)
              {
                ret->stdin_once = 0;
                ret->stdin_once_present = 1;
              }
          }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "Env", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->env_len = len;
            ret->env = calloc (len + 1, sizeof (*ret->env));
            if (ret->env == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                if (val != NULL)
                  {
                    char *str = YAJL_GET_STRING (val);
                    ret->env[i] = strdup (str ? str : "");
                    if (ret->env[i] == NULL)
                      return NULL;
                  }
              }
        }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "Cmd", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->cmd_len = len;
            ret->cmd = calloc (len + 1, sizeof (*ret->cmd));
            if (ret->cmd == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                if (val != NULL)
                  {
                    char *str = YAJL_GET_STRING (val);
                    ret->cmd[i] = strdup (str ? str : "");
                    if (ret->cmd[i] == NULL)
                      return NULL;
                  }
              }
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "ArgsEscaped", yajl_t_true);
        if (val != NULL)
          {
            ret->args_escaped = YAJL_IS_TRUE(val);
            ret->args_escaped_present = 1;
          }
        else
          {
            val = get_val (tree, "ArgsEscaped", yajl_t_false);
            if (val != NULL)
              {
                ret->args_escaped = 0;
                ret->args_escaped_present = 1;
              }
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "Image", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->image = strdup (str ? str : "");
            if (ret->image == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "ImageRef", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->image_ref = strdup (str ? str : "");
            if (ret->image_ref == NULL)
              return NULL;
          }
      }
    while (0);
    ret->volumes = make_defs_map_string_object (get_val (tree, "Volumes", yajl_t_object), ctx, err);
    if (ret->volumes == NULL && *err != 0)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "WorkingDir", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->working_dir = strdup (str ? str : "");
            if (ret->working_dir == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "Entrypoint", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->entrypoint_len = len;
            ret->entrypoint = calloc (len + 1, sizeof (*ret->entrypoint));
            if (ret->entrypoint == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                if (val != NULL)
                  {
                    char *str = YAJL_GET_STRING (val);
                    ret->entrypoint[i] = strdup (str ? str : "");
                    if (ret->entrypoint[i] == NULL)
                      return NULL;
                  }
              }
        }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "NetworkDisabled", yajl_t_true);
        if (val != NULL)
          {
            ret->network_disabled = YAJL_IS_TRUE(val);
            ret->network_disabled_present = 1;
          }
        else
          {
            val = get_val (tree, "NetworkDisabled", yajl_t_false);
            if (val != NULL)
              {
                ret->network_disabled = 0;
                ret->network_disabled_present = 1;
              }
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
        yajl_val tmp = get_val (tree, "Onbuild", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->onbuild_len = len;
            ret->onbuild = calloc (len + 1, sizeof (*ret->onbuild));
            if (ret->onbuild == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                if (val != NULL)
                  {
                    char *str = YAJL_GET_STRING (val);
                    ret->onbuild[i] = strdup (str ? str : "");
                    if (ret->onbuild[i] == NULL)
                      return NULL;
                  }
              }
        }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "Labels", yajl_t_object);
        if (tmp != NULL)
          {
            ret->labels = make_json_map_string_string (tmp, ctx, err);
            if (ret->labels == NULL)
              {
                char *new_error = NULL;
                if (asprintf (&new_error, "Value error for key 'Labels': %s", *err ? *err : "null") < 0)
                  new_error = strdup ("error allocating memory");
                free (*err);
                *err = new_error;
                return NULL;
              }
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "LogDriver", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->log_driver = strdup (str ? str : "");
            if (ret->log_driver == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "Annotations", yajl_t_object);
        if (tmp != NULL)
          {
            ret->annotations = make_json_map_string_string (tmp, ctx, err);
            if (ret->annotations == NULL)
              {
                char *new_error = NULL;
                if (asprintf (&new_error, "Value error for key 'Annotations': %s", *err ? *err : "null") < 0)
                  new_error = strdup ("error allocating memory");
                free (*err);
                *err = new_error;
                return NULL;
              }
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "StopSignal", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->stop_signal = strdup (str ? str : "");
            if (ret->stop_signal == NULL)
              return NULL;
          }
      }
    while (0);
    ret->healthcheck = make_defs_health_check (get_val (tree, "Healthcheck", yajl_t_object), ctx, err);
    if (ret->healthcheck == NULL && *err != 0)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "SystemContainer", yajl_t_true);
        if (val != NULL)
          {
            ret->system_container = YAJL_IS_TRUE(val);
            ret->system_container_present = 1;
          }
        else
          {
            val = get_val (tree, "SystemContainer", yajl_t_false);
            if (val != NULL)
              {
                ret->system_container = 0;
                ret->system_container_present = 1;
              }
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "NsChangeOpt", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->ns_change_opt = strdup (str ? str : "");
            if (ret->ns_change_opt == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val tmp = get_val (tree, "Mounts", yajl_t_array);
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
                if (val != NULL)
                  {
                    char *str = YAJL_GET_STRING (val);
                    ret->mounts[i] = strdup (str ? str : "");
                    if (ret->mounts[i] == NULL)
                      return NULL;
                  }
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
          {if (strcmp (tree->u.object.keys[i], "Hostname")
                && strcmp (tree->u.object.keys[i], "Domainname")
                && strcmp (tree->u.object.keys[i], "User")
                && strcmp (tree->u.object.keys[i], "AttachStdin")
                && strcmp (tree->u.object.keys[i], "AttachStdout")
                && strcmp (tree->u.object.keys[i], "AttachStderr")
                && strcmp (tree->u.object.keys[i], "ExposedPorts")
                && strcmp (tree->u.object.keys[i], "PublishService")
                && strcmp (tree->u.object.keys[i], "Tty")
                && strcmp (tree->u.object.keys[i], "OpenStdin")
                && strcmp (tree->u.object.keys[i], "StdinOnce")
                && strcmp (tree->u.object.keys[i], "Env")
                && strcmp (tree->u.object.keys[i], "Cmd")
                && strcmp (tree->u.object.keys[i], "ArgsEscaped")
                && strcmp (tree->u.object.keys[i], "Image")
                && strcmp (tree->u.object.keys[i], "ImageRef")
                && strcmp (tree->u.object.keys[i], "Volumes")
                && strcmp (tree->u.object.keys[i], "WorkingDir")
                && strcmp (tree->u.object.keys[i], "Entrypoint")
                && strcmp (tree->u.object.keys[i], "NetworkDisabled")
                && strcmp (tree->u.object.keys[i], "MacAddress")
                && strcmp (tree->u.object.keys[i], "Onbuild")
                && strcmp (tree->u.object.keys[i], "Labels")
                && strcmp (tree->u.object.keys[i], "LogDriver")
                && strcmp (tree->u.object.keys[i], "Annotations")
                && strcmp (tree->u.object.keys[i], "StopSignal")
                && strcmp (tree->u.object.keys[i], "Healthcheck")
                && strcmp (tree->u.object.keys[i], "SystemContainer")
                && strcmp (tree->u.object.keys[i], "NsChangeOpt")
                && strcmp (tree->u.object.keys[i], "Mounts")){
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
free_container_config (container_config *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr->hostname);
    ptr->hostname = NULL;
    free (ptr->domainname);
    ptr->domainname = NULL;
    free (ptr->user);
    ptr->user = NULL;
    free_defs_map_string_object (ptr->exposed_ports);
    ptr->exposed_ports = NULL;
    free (ptr->publish_service);
    ptr->publish_service = NULL;
    if (ptr->env != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->env_len; i++)
          {
            if (ptr->env[i] != NULL)
              {
                free (ptr->env[i]);
                ptr->env[i] = NULL;
              }
          }
        free (ptr->env);
        ptr->env = NULL;
    }
    if (ptr->cmd != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->cmd_len; i++)
          {
            if (ptr->cmd[i] != NULL)
              {
                free (ptr->cmd[i]);
                ptr->cmd[i] = NULL;
              }
          }
        free (ptr->cmd);
        ptr->cmd = NULL;
    }
    free (ptr->image);
    ptr->image = NULL;
    free (ptr->image_ref);
    ptr->image_ref = NULL;
    free_defs_map_string_object (ptr->volumes);
    ptr->volumes = NULL;
    free (ptr->working_dir);
    ptr->working_dir = NULL;
    if (ptr->entrypoint != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->entrypoint_len; i++)
          {
            if (ptr->entrypoint[i] != NULL)
              {
                free (ptr->entrypoint[i]);
                ptr->entrypoint[i] = NULL;
              }
          }
        free (ptr->entrypoint);
        ptr->entrypoint = NULL;
    }
    free (ptr->mac_address);
    ptr->mac_address = NULL;
    if (ptr->onbuild != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->onbuild_len; i++)
          {
            if (ptr->onbuild[i] != NULL)
              {
                free (ptr->onbuild[i]);
                ptr->onbuild[i] = NULL;
              }
          }
        free (ptr->onbuild);
        ptr->onbuild = NULL;
    }
    free_json_map_string_string (ptr->labels);
    ptr->labels = NULL;
    free (ptr->log_driver);
    ptr->log_driver = NULL;
    free_json_map_string_string (ptr->annotations);
    ptr->annotations = NULL;
    free (ptr->stop_signal);
    ptr->stop_signal = NULL;
    if (ptr->healthcheck != NULL)
      {
        free_defs_health_check (ptr->healthcheck);
        ptr->healthcheck = NULL;
      }
    free (ptr->ns_change_opt);
    ptr->ns_change_opt = NULL;
    if (ptr->mounts != NULL)
      {
        size_t i;
        for (i = 0; i < ptr->mounts_len; i++)
          {
            if (ptr->mounts[i] != NULL)
              {
                free (ptr->mounts[i]);
                ptr->mounts[i] = NULL;
              }
          }
        free (ptr->mounts);
        ptr->mounts = NULL;
    }
    yajl_tree_free (ptr->_residual);
    ptr->_residual = NULL;
    free (ptr);
}

yajl_gen_status
gen_container_config (yajl_gen g, const container_config *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->hostname != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Hostname"), 8 /* strlen ("Hostname") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->hostname != NULL)
            str = ptr->hostname;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->domainname != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Domainname"), 10 /* strlen ("Domainname") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->domainname != NULL)
            str = ptr->domainname;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->user != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("User"), 4 /* strlen ("User") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->user != NULL)
            str = ptr->user;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->attach_stdin_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("AttachStdin"), 11 /* strlen ("AttachStdin") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->attach_stdin)
            b = ptr->attach_stdin;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->attach_stdout_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("AttachStdout"), 12 /* strlen ("AttachStdout") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->attach_stdout)
            b = ptr->attach_stdout;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->attach_stderr_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("AttachStderr"), 12 /* strlen ("AttachStderr") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->attach_stderr)
            b = ptr->attach_stderr;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->exposed_ports != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("ExposedPorts"), 12 /* strlen ("ExposedPorts") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_defs_map_string_object (g, ptr != NULL ? ptr->exposed_ports : NULL, ctx, err);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->publish_service != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("PublishService"), 14 /* strlen ("PublishService") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->publish_service != NULL)
            str = ptr->publish_service;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->tty_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Tty"), 3 /* strlen ("Tty") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->tty)
            b = ptr->tty;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->open_stdin_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("OpenStdin"), 9 /* strlen ("OpenStdin") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->open_stdin)
            b = ptr->open_stdin;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->stdin_once_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("StdinOnce"), 9 /* strlen ("StdinOnce") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->stdin_once)
            b = ptr->stdin_once;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->env != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Env"), 3 /* strlen ("Env") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->env != NULL)
          len = ptr->env_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(ptr->env[i]), strlen (ptr->env[i]));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->cmd != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Cmd"), 3 /* strlen ("Cmd") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->cmd != NULL)
          len = ptr->cmd_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(ptr->cmd[i]), strlen (ptr->cmd[i]));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->args_escaped_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("ArgsEscaped"), 11 /* strlen ("ArgsEscaped") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->args_escaped)
            b = ptr->args_escaped;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->image != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Image"), 5 /* strlen ("Image") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->image != NULL)
            str = ptr->image;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->image_ref != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("ImageRef"), 8 /* strlen ("ImageRef") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->image_ref != NULL)
            str = ptr->image_ref;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->volumes != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Volumes"), 7 /* strlen ("Volumes") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_defs_map_string_object (g, ptr != NULL ? ptr->volumes : NULL, ctx, err);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->working_dir != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("WorkingDir"), 10 /* strlen ("WorkingDir") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->working_dir != NULL)
            str = ptr->working_dir;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->entrypoint != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Entrypoint"), 10 /* strlen ("Entrypoint") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->entrypoint != NULL)
          len = ptr->entrypoint_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(ptr->entrypoint[i]), strlen (ptr->entrypoint[i]));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->network_disabled_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("NetworkDisabled"), 15 /* strlen ("NetworkDisabled") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->network_disabled)
            b = ptr->network_disabled;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
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
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->onbuild != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Onbuild"), 7 /* strlen ("Onbuild") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->onbuild != NULL)
          len = ptr->onbuild_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(ptr->onbuild[i]), strlen (ptr->onbuild[i]));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->labels != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("labels"), 6 /* strlen ("labels") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_json_map_string_string (g, ptr ? ptr->labels : NULL, ctx, err);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->log_driver != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("LogDriver"), 9 /* strlen ("LogDriver") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->log_driver != NULL)
            str = ptr->log_driver;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->annotations != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("annotations"), 11 /* strlen ("annotations") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_json_map_string_string (g, ptr ? ptr->annotations : NULL, ctx, err);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->stop_signal != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("StopSignal"), 10 /* strlen ("StopSignal") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->stop_signal != NULL)
            str = ptr->stop_signal;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->healthcheck != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Healthcheck"), 11 /* strlen ("Healthcheck") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_defs_health_check (g, ptr != NULL ? ptr->healthcheck : NULL, ctx, err);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->system_container_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("SystemContainer"), 15 /* strlen ("SystemContainer") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->system_container)
            b = ptr->system_container;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->ns_change_opt != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("NsChangeOpt"), 11 /* strlen ("NsChangeOpt") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->ns_change_opt != NULL)
            str = ptr->ns_change_opt;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->mounts != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Mounts"), 6 /* strlen ("Mounts") */);
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
            stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(ptr->mounts[i]), strlen (ptr->mounts[i]));
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
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


container_config *
container_config_parse_file (const char *filename, const struct parser_context *ctx, parser_error *err)
{
container_config *ptr = NULL;size_t filesize;
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
      }ptr = container_config_parse_data (content, ctx, err);return ptr;
}
container_config * 
container_config_parse_file_stream (FILE *stream, const struct parser_context *ctx, parser_error *err)
{container_config *ptr = NULL;
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
ptr = container_config_parse_data (content, ctx, err);return ptr;
}

define_cleaner_function (yajl_val, yajl_tree_free)

 container_config * container_config_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)
 { 
  container_config *ptr = NULL;__auto_cleanup(yajl_tree_free) yajl_val tree = NULL;
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
ptr = make_container_config (tree, ctx, err);return ptr; 
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
container_config_generate_json (const container_config *ptr, const struct parser_context *ctx, parser_error *err){
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

if (yajl_gen_status_ok != gen_container_config (g, ptr, ctx, err))  {
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
