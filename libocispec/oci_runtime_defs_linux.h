// Generated from defs-linux.json. Do not edit!
#ifndef OCI_RUNTIME_DEFS_LINUX_SCHEMA_H
#define OCI_RUNTIME_DEFS_LINUX_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "oci_runtime_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *domain;

    char **flags;
    size_t flags_len;

    yajl_val _residual;
}
oci_runtime_defs_linux_personality;

void free_oci_runtime_defs_linux_personality (oci_runtime_defs_linux_personality *ptr);

oci_runtime_defs_linux_personality *make_oci_runtime_defs_linux_personality (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_personality (yajl_gen g, const oci_runtime_defs_linux_personality *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    uint32_t index;

    uint64_t value;

    uint64_t value_two;

    char *op;

    yajl_val _residual;

    unsigned int index_present : 1;
    unsigned int value_present : 1;
    unsigned int value_two_present : 1;
}
oci_runtime_defs_linux_syscall_arg;

void free_oci_runtime_defs_linux_syscall_arg (oci_runtime_defs_linux_syscall_arg *ptr);

oci_runtime_defs_linux_syscall_arg *make_oci_runtime_defs_linux_syscall_arg (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_syscall_arg (yajl_gen g, const oci_runtime_defs_linux_syscall_arg *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char **names;
    size_t names_len;

    char *action;

    uint32_t errno_ret;

    oci_runtime_defs_linux_syscall_arg **args;
    size_t args_len;

    yajl_val _residual;

    unsigned int errno_ret_present : 1;
}
oci_runtime_defs_linux_syscall;

void free_oci_runtime_defs_linux_syscall (oci_runtime_defs_linux_syscall *ptr);

oci_runtime_defs_linux_syscall *make_oci_runtime_defs_linux_syscall (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_syscall (yajl_gen g, const oci_runtime_defs_linux_syscall *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *type;

    char *path;

    int file_mode;

    int64_t major;

    int64_t minor;

    uid_t uid;

    gid_t gid;

    yajl_val _residual;

    unsigned int file_mode_present : 1;
    unsigned int major_present : 1;
    unsigned int minor_present : 1;
    unsigned int uid_present : 1;
    unsigned int gid_present : 1;
}
oci_runtime_defs_linux_device;

void free_oci_runtime_defs_linux_device (oci_runtime_defs_linux_device *ptr);

oci_runtime_defs_linux_device *make_oci_runtime_defs_linux_device (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_device (yajl_gen g, const oci_runtime_defs_linux_device *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int64_t major;

    int64_t minor;

    yajl_val _residual;

    unsigned int major_present : 1;
    unsigned int minor_present : 1;
}
oci_runtime_defs_linux_block_io_device;

void free_oci_runtime_defs_linux_block_io_device (oci_runtime_defs_linux_block_io_device *ptr);

oci_runtime_defs_linux_block_io_device *make_oci_runtime_defs_linux_block_io_device (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_block_io_device (yajl_gen g, const oci_runtime_defs_linux_block_io_device *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int64_t major;

    int64_t minor;

    uint16_t weight;

    uint16_t leaf_weight;

    yajl_val _residual;

    unsigned int major_present : 1;
    unsigned int minor_present : 1;
    unsigned int weight_present : 1;
    unsigned int leaf_weight_present : 1;
}
oci_runtime_defs_linux_block_io_device_weight;

void free_oci_runtime_defs_linux_block_io_device_weight (oci_runtime_defs_linux_block_io_device_weight *ptr);

oci_runtime_defs_linux_block_io_device_weight *make_oci_runtime_defs_linux_block_io_device_weight (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_block_io_device_weight (yajl_gen g, const oci_runtime_defs_linux_block_io_device_weight *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int64_t major;

    int64_t minor;

    uint64_t rate;

    yajl_val _residual;

    unsigned int major_present : 1;
    unsigned int minor_present : 1;
    unsigned int rate_present : 1;
}
oci_runtime_defs_linux_block_io_device_throttle;

void free_oci_runtime_defs_linux_block_io_device_throttle (oci_runtime_defs_linux_block_io_device_throttle *ptr);

oci_runtime_defs_linux_block_io_device_throttle *make_oci_runtime_defs_linux_block_io_device_throttle (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_block_io_device_throttle (yajl_gen g, const oci_runtime_defs_linux_block_io_device_throttle *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    bool allow;

    char *type;

    int64_t major;

    int64_t minor;

    char *access;

    yajl_val _residual;

    unsigned int allow_present : 1;
    unsigned int major_present : 1;
    unsigned int minor_present : 1;
}
oci_runtime_defs_linux_device_cgroup;

void free_oci_runtime_defs_linux_device_cgroup (oci_runtime_defs_linux_device_cgroup *ptr);

oci_runtime_defs_linux_device_cgroup *make_oci_runtime_defs_linux_device_cgroup (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_device_cgroup (yajl_gen g, const oci_runtime_defs_linux_device_cgroup *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *name;

    uint32_t priority;

    yajl_val _residual;

    unsigned int priority_present : 1;
}
oci_runtime_defs_linux_network_interface_priority;

void free_oci_runtime_defs_linux_network_interface_priority (oci_runtime_defs_linux_network_interface_priority *ptr);

oci_runtime_defs_linux_network_interface_priority *make_oci_runtime_defs_linux_network_interface_priority (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_network_interface_priority (yajl_gen g, const oci_runtime_defs_linux_network_interface_priority *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    uint32_t hca_handles;

    uint32_t hca_objects;

    yajl_val _residual;

    unsigned int hca_handles_present : 1;
    unsigned int hca_objects_present : 1;
}
oci_runtime_defs_linux_rdma;

void free_oci_runtime_defs_linux_rdma (oci_runtime_defs_linux_rdma *ptr);

oci_runtime_defs_linux_rdma *make_oci_runtime_defs_linux_rdma (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_rdma (yajl_gen g, const oci_runtime_defs_linux_rdma *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *type;

    char *path;

    yajl_val _residual;
}
oci_runtime_defs_linux_namespace_reference;

void free_oci_runtime_defs_linux_namespace_reference (oci_runtime_defs_linux_namespace_reference *ptr);

oci_runtime_defs_linux_namespace_reference *make_oci_runtime_defs_linux_namespace_reference (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_namespace_reference (yajl_gen g, const oci_runtime_defs_linux_namespace_reference *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int64_t secs;

    uint32_t nanosecs;

    yajl_val _residual;

    unsigned int secs_present : 1;
    unsigned int nanosecs_present : 1;
}
oci_runtime_defs_linux_time_offsets;

void free_oci_runtime_defs_linux_time_offsets (oci_runtime_defs_linux_time_offsets *ptr);

oci_runtime_defs_linux_time_offsets *make_oci_runtime_defs_linux_time_offsets (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_defs_linux_time_offsets (yajl_gen g, const oci_runtime_defs_linux_time_offsets *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

