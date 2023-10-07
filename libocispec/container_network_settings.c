/* Generated from network-settings.json. Do not edit!  */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include "read-file.h"
#include "container_network_settings.h"

#define YAJL_GET_ARRAY_NO_CHECK(v) (&(v)->u.array)
#define YAJL_GET_OBJECT_NO_CHECK(v) (&(v)->u.object)
define_cleaner_function (container_network_settings *, free_container_network_settings)
container_network_settings *
make_container_network_settings (yajl_val tree, const struct parser_context *ctx, parser_error *err)
{
    __auto_cleanup(free_container_network_settings) container_network_settings *ret = NULL;
    *err = NULL;
    (void) ctx;  /* Silence compiler warning.  */
    if (tree == NULL)
      return NULL;
    ret = calloc (1, sizeof (*ret));
    if (ret == NULL)
      return NULL;
    do
      {
        yajl_val val = get_val (tree, "Bridge", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->bridge = strdup (str ? str : "");
            if (ret->bridge == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "SandboxID", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->sandbox_id = strdup (str ? str : "");
            if (ret->sandbox_id == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "LinkLocalIPv6Address", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->link_local_i_pv6address = strdup (str ? str : "");
            if (ret->link_local_i_pv6address == NULL)
              return NULL;
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "LinkLocalIPv6PrefixLen", yajl_t_number);
        if (val != NULL)
          {
            int invalid;
            if (! YAJL_IS_NUMBER (val))
              {
                *err = strdup ("invalid type");
                return NULL;
              }
            invalid = common_safe_int (YAJL_GET_NUMBER (val), (int *)&ret->link_local_i_pv6prefix_len);
            if (invalid)
              {
                if (asprintf (err, "Invalid value '%s' with type 'integer' for key 'LinkLocalIPv6PrefixLen': %s", YAJL_GET_NUMBER (val), strerror (-invalid)) < 0)
                    *err = strdup ("error allocating memory");
                return NULL;
            }
            ret->link_local_i_pv6prefix_len_present = 1;
        }
      }
    while (0);
    ret->ports = make_defs_map_string_object_port_bindings (get_val (tree, "Ports", yajl_t_object), ctx, err);
    if (ret->ports == NULL && *err != 0)
      return NULL;
    do
      {
        yajl_val tmp = get_val (tree, "CNIPorts", yajl_t_array);
        if (tmp != NULL && YAJL_GET_ARRAY (tmp) != NULL)
          {
            size_t i;
            size_t len = YAJL_GET_ARRAY_NO_CHECK (tmp)->len;
            yajl_val *values = YAJL_GET_ARRAY_NO_CHECK (tmp)->values;
            ret->cni_ports_len = len;
            ret->cni_ports = calloc (len + 1, sizeof (*ret->cni_ports));
            if (ret->cni_ports == NULL)
              return NULL;
            for (i = 0; i < len; i++)
              {
                yajl_val val = values[i];
                ret->cni_ports[i] = make_cni_inner_port_mapping (val, ctx, err);
                if (ret->cni_ports[i] == NULL)
                  return NULL;
              }
          }
      }
    while (0);
    do
      {
        yajl_val val = get_val (tree, "SandboxKey", yajl_t_string);
        if (val != NULL)
          {
            char *str = YAJL_GET_STRING (val);
            ret->sandbox_key = strdup (str ? str : "");
            if (ret->sandbox_key == NULL)
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
        yajl_val val = get_val (tree, "Activation", yajl_t_true);
        if (val != NULL)
          {
            ret->activation = YAJL_IS_TRUE(val);
            ret->activation_present = 1;
          }
        else
          {
            val = get_val (tree, "Activation", yajl_t_false);
            if (val != NULL)
              {
                ret->activation = 0;
                ret->activation_present = 1;
              }
          }
      }
    while (0);
    ret->networks = make_defs_map_string_object_networks (get_val (tree, "Networks", yajl_t_object), ctx, err);
    if (ret->networks == NULL && *err != 0)
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
          {if (strcmp (tree->u.object.keys[i], "Bridge")
                && strcmp (tree->u.object.keys[i], "SandboxID")
                && strcmp (tree->u.object.keys[i], "LinkLocalIPv6Address")
                && strcmp (tree->u.object.keys[i], "LinkLocalIPv6PrefixLen")
                && strcmp (tree->u.object.keys[i], "Ports")
                && strcmp (tree->u.object.keys[i], "CNIPorts")
                && strcmp (tree->u.object.keys[i], "SandboxKey")
                && strcmp (tree->u.object.keys[i], "EndpointID")
                && strcmp (tree->u.object.keys[i], "Gateway")
                && strcmp (tree->u.object.keys[i], "GlobalIPv6Address")
                && strcmp (tree->u.object.keys[i], "GlobalIPv6PrefixLen")
                && strcmp (tree->u.object.keys[i], "IPAddress")
                && strcmp (tree->u.object.keys[i], "IPPrefixLen")
                && strcmp (tree->u.object.keys[i], "IPv6Gateway")
                && strcmp (tree->u.object.keys[i], "MacAddress")
                && strcmp (tree->u.object.keys[i], "Activation")
                && strcmp (tree->u.object.keys[i], "Networks")){
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
free_container_network_settings (container_network_settings *ptr)
{
    if (ptr == NULL)
        return;
    free (ptr->bridge);
    ptr->bridge = NULL;
    free (ptr->sandbox_id);
    ptr->sandbox_id = NULL;
    free (ptr->link_local_i_pv6address);
    ptr->link_local_i_pv6address = NULL;
    free_defs_map_string_object_port_bindings (ptr->ports);
    ptr->ports = NULL;
    if (ptr->cni_ports != NULL)      {
        size_t i;
        for (i = 0; i < ptr->cni_ports_len; i++)
          {
          if (ptr->cni_ports[i] != NULL)
            {
              free_cni_inner_port_mapping (ptr->cni_ports[i]);
              ptr->cni_ports[i] = NULL;
            }
          }
        free (ptr->cni_ports);
        ptr->cni_ports = NULL;
      }
    free (ptr->sandbox_key);
    ptr->sandbox_key = NULL;
    free (ptr->endpoint_id);
    ptr->endpoint_id = NULL;
    free (ptr->gateway);
    ptr->gateway = NULL;
    free (ptr->global_i_pv6address);
    ptr->global_i_pv6address = NULL;
    free (ptr->ip_address);
    ptr->ip_address = NULL;
    free (ptr->i_pv6gateway);
    ptr->i_pv6gateway = NULL;
    free (ptr->mac_address);
    ptr->mac_address = NULL;
    free_defs_map_string_object_networks (ptr->networks);
    ptr->networks = NULL;
    yajl_tree_free (ptr->_residual);
    ptr->_residual = NULL;
    free (ptr);
}

yajl_gen_status
gen_container_network_settings (yajl_gen g, const container_network_settings *ptr, const struct parser_context *ctx, parser_error *err)
{
    yajl_gen_status stat = yajl_gen_status_ok;
    *err = NULL;
    (void) ptr;  /* Silence compiler warning.  */
    stat = yajl_gen_map_open ((yajl_gen) g);
    if (stat != yajl_gen_status_ok)
        GEN_SET_ERROR_AND_RETURN (stat, err);
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->bridge != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Bridge"), 6 /* strlen ("Bridge") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->bridge != NULL)
            str = ptr->bridge;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->sandbox_id != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("SandboxID"), 9 /* strlen ("SandboxID") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->sandbox_id != NULL)
            str = ptr->sandbox_id;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->link_local_i_pv6address != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("LinkLocalIPv6Address"), 20 /* strlen ("LinkLocalIPv6Address") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->link_local_i_pv6address != NULL)
            str = ptr->link_local_i_pv6address;
        stat = yajl_gen_string ((yajl_gen)g, (const unsigned char *)(str), strlen (str));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->link_local_i_pv6prefix_len_present))
      {
        long long int num = 0;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("LinkLocalIPv6PrefixLen"), 22 /* strlen ("LinkLocalIPv6PrefixLen") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->link_local_i_pv6prefix_len)
            num = (long long int)ptr->link_local_i_pv6prefix_len;
        stat = map_int (g, num);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->ports != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Ports"), 5 /* strlen ("Ports") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_defs_map_string_object_port_bindings (g, ptr != NULL ? ptr->ports : NULL, ctx, err);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->cni_ports != NULL))
      {
        size_t len = 0, i;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("CNIPorts"), 8 /* strlen ("CNIPorts") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->cni_ports != NULL)
            len = ptr->cni_ports_len;
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 0);
        stat = yajl_gen_array_open ((yajl_gen) g);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        for (i = 0; i < len; i++)
          {
            stat = gen_cni_inner_port_mapping (g, ptr->cni_ports[i], ctx, err);
            if (stat != yajl_gen_status_ok)
                GEN_SET_ERROR_AND_RETURN (stat, err);
          }
        stat = yajl_gen_array_close ((yajl_gen) g);
        if (!len && !(ctx->options & OPT_GEN_SIMPLIFY))
            yajl_gen_config (g, yajl_gen_beautify, 1);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->sandbox_key != NULL))
      {
        char *str = "";
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("SandboxKey"), 10 /* strlen ("SandboxKey") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->sandbox_key != NULL)
            str = ptr->sandbox_key;
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
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->activation_present))
      {
        bool b = false;
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Activation"), 10 /* strlen ("Activation") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        if (ptr != NULL && ptr->activation)
            b = ptr->activation;
        
        stat = yajl_gen_bool ((yajl_gen)g, (int)(b));
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
      }
    if ((ctx->options & OPT_GEN_KEY_VALUE) || (ptr != NULL && ptr->networks != NULL))
      {
        stat = yajl_gen_string ((yajl_gen) g, (const unsigned char *)("Networks"), 8 /* strlen ("Networks") */);
        if (stat != yajl_gen_status_ok)
            GEN_SET_ERROR_AND_RETURN (stat, err);
        stat = gen_defs_map_string_object_networks (g, ptr != NULL ? ptr->networks : NULL, ctx, err);
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


container_network_settings *
container_network_settings_parse_file (const char *filename, const struct parser_context *ctx, parser_error *err)
{
container_network_settings *ptr = NULL;size_t filesize;
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
      }ptr = container_network_settings_parse_data (content, ctx, err);return ptr;
}
container_network_settings * 
container_network_settings_parse_file_stream (FILE *stream, const struct parser_context *ctx, parser_error *err)
{container_network_settings *ptr = NULL;
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
ptr = container_network_settings_parse_data (content, ctx, err);return ptr;
}

define_cleaner_function (yajl_val, yajl_tree_free)

 container_network_settings * container_network_settings_parse_data (const char *jsondata, const struct parser_context *ctx, parser_error *err)
 { 
  container_network_settings *ptr = NULL;__auto_cleanup(yajl_tree_free) yajl_val tree = NULL;
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
ptr = make_container_network_settings (tree, ctx, err);return ptr; 
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
container_network_settings_generate_json (const container_network_settings *ptr, const struct parser_context *ctx, parser_error *err){
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

if (yajl_gen_status_ok != gen_container_network_settings (g, ptr, ctx, err))  {
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
