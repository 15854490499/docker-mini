// Generated from config-linux.json. Do not edit!
#ifndef OCI_RUNTIME_CONFIG_LINUX_SCHEMA_H
#define OCI_RUNTIME_CONFIG_LINUX_SCHEMA_H

#include <sys/types.h>
#include <stdint.h>
#include "json_common.h"
#include "oci_runtime_defs_linux.h"
#include "oci_runtime_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int64_t limit;

    yajl_val _residual;

    unsigned int limit_present : 1;
}
oci_runtime_config_linux_resources_pids;

void free_oci_runtime_config_linux_resources_pids (oci_runtime_config_linux_resources_pids *ptr);

oci_runtime_config_linux_resources_pids *make_oci_runtime_config_linux_resources_pids (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_resources_pids (yajl_gen g, const oci_runtime_config_linux_resources_pids *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    uint16_t weight;

    uint16_t leaf_weight;

    oci_runtime_defs_linux_block_io_device_throttle **throttle_read_bps_device;
    size_t throttle_read_bps_device_len;

    oci_runtime_defs_linux_block_io_device_throttle **throttle_write_bps_device;
    size_t throttle_write_bps_device_len;

    oci_runtime_defs_linux_block_io_device_throttle **throttle_read_iops_device;
    size_t throttle_read_iops_device_len;

    oci_runtime_defs_linux_block_io_device_throttle **throttle_write_iops_device;
    size_t throttle_write_iops_device_len;

    oci_runtime_defs_linux_block_io_device_weight **weight_device;
    size_t weight_device_len;

    yajl_val _residual;

    unsigned int weight_present : 1;
    unsigned int leaf_weight_present : 1;
}
oci_runtime_config_linux_resources_block_io;

void free_oci_runtime_config_linux_resources_block_io (oci_runtime_config_linux_resources_block_io *ptr);

oci_runtime_config_linux_resources_block_io *make_oci_runtime_config_linux_resources_block_io (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_resources_block_io (yajl_gen g, const oci_runtime_config_linux_resources_block_io *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *cpus;

    char *mems;

    uint64_t period;

    int64_t quota;

    uint64_t burst;

    uint64_t realtime_period;

    int64_t realtime_runtime;

    uint64_t shares;

    int64_t idle;

    yajl_val _residual;

    unsigned int period_present : 1;
    unsigned int quota_present : 1;
    unsigned int burst_present : 1;
    unsigned int realtime_period_present : 1;
    unsigned int realtime_runtime_present : 1;
    unsigned int shares_present : 1;
    unsigned int idle_present : 1;
}
oci_runtime_config_linux_resources_cpu;

void free_oci_runtime_config_linux_resources_cpu (oci_runtime_config_linux_resources_cpu *ptr);

oci_runtime_config_linux_resources_cpu *make_oci_runtime_config_linux_resources_cpu (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_resources_cpu (yajl_gen g, const oci_runtime_config_linux_resources_cpu *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *page_size;
    uint64_t limit;
    unsigned int limit_present : 1;
}
oci_runtime_config_linux_resources_hugepage_limits_element;

void free_oci_runtime_config_linux_resources_hugepage_limits_element (oci_runtime_config_linux_resources_hugepage_limits_element *ptr);

oci_runtime_config_linux_resources_hugepage_limits_element *make_oci_runtime_config_linux_resources_hugepage_limits_element (yajl_val tree, const struct parser_context *ctx, parser_error *err);

typedef struct {
    int64_t kernel;

    int64_t kernel_tcp;

    int64_t limit;

    int64_t reservation;

    int64_t swap;

    uint64_t swappiness;

    bool disable_oom_killer;

    bool use_hierarchy;

    bool check_before_update;

    yajl_val _residual;

    unsigned int kernel_present : 1;
    unsigned int kernel_tcp_present : 1;
    unsigned int limit_present : 1;
    unsigned int reservation_present : 1;
    unsigned int swap_present : 1;
    unsigned int swappiness_present : 1;
    unsigned int disable_oom_killer_present : 1;
    unsigned int use_hierarchy_present : 1;
    unsigned int check_before_update_present : 1;
}
oci_runtime_config_linux_resources_memory;

void free_oci_runtime_config_linux_resources_memory (oci_runtime_config_linux_resources_memory *ptr);

oci_runtime_config_linux_resources_memory *make_oci_runtime_config_linux_resources_memory (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_resources_memory (yajl_gen g, const oci_runtime_config_linux_resources_memory *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    uint32_t class_id;

    oci_runtime_defs_linux_network_interface_priority **priorities;
    size_t priorities_len;

    yajl_val _residual;

    unsigned int class_id_present : 1;
}
oci_runtime_config_linux_resources_network;

void free_oci_runtime_config_linux_resources_network (oci_runtime_config_linux_resources_network *ptr);

oci_runtime_config_linux_resources_network *make_oci_runtime_config_linux_resources_network (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_resources_network (yajl_gen g, const oci_runtime_config_linux_resources_network *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char unuseful; // unuseful definition to avoid empty struct
}
oci_runtime_config_linux_resources_rdma;

void free_oci_runtime_config_linux_resources_rdma (oci_runtime_config_linux_resources_rdma *ptr);

oci_runtime_config_linux_resources_rdma *make_oci_runtime_config_linux_resources_rdma (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_resources_rdma (yajl_gen g, const oci_runtime_config_linux_resources_rdma *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    json_map_string_string *unified;

    oci_runtime_defs_linux_device_cgroup **devices;
    size_t devices_len;

    oci_runtime_config_linux_resources_pids *pids;

    oci_runtime_config_linux_resources_block_io *block_io;

    oci_runtime_config_linux_resources_cpu *cpu;

    oci_runtime_config_linux_resources_hugepage_limits_element **hugepage_limits;
    size_t hugepage_limits_len;

    oci_runtime_config_linux_resources_memory *memory;

    oci_runtime_config_linux_resources_network *network;

    oci_runtime_config_linux_resources_rdma *rdma;

    yajl_val _residual;
}
oci_runtime_config_linux_resources;

void free_oci_runtime_config_linux_resources (oci_runtime_config_linux_resources *ptr);

oci_runtime_config_linux_resources *make_oci_runtime_config_linux_resources (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_resources (yajl_gen g, const oci_runtime_config_linux_resources *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *default_action;

    uint32_t default_errno_ret;

    char **flags;
    size_t flags_len;

    char *listener_path;

    char *listener_metadata;

    char **architectures;
    size_t architectures_len;

    oci_runtime_defs_linux_syscall **syscalls;
    size_t syscalls_len;

    yajl_val _residual;

    unsigned int default_errno_ret_present : 1;
}
oci_runtime_config_linux_seccomp;

void free_oci_runtime_config_linux_seccomp (oci_runtime_config_linux_seccomp *ptr);

oci_runtime_config_linux_seccomp *make_oci_runtime_config_linux_seccomp (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_seccomp (yajl_gen g, const oci_runtime_config_linux_seccomp *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    char *clos_id;

    char *l3cache_schema;

    char *mem_bw_schema;

    bool enable_cmt;

    bool enable_mbm;

    yajl_val _residual;

    unsigned int enable_cmt_present : 1;
    unsigned int enable_mbm_present : 1;
}
oci_runtime_config_linux_intel_rdt;

void free_oci_runtime_config_linux_intel_rdt (oci_runtime_config_linux_intel_rdt *ptr);

oci_runtime_config_linux_intel_rdt *make_oci_runtime_config_linux_intel_rdt (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_intel_rdt (yajl_gen g, const oci_runtime_config_linux_intel_rdt *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    oci_runtime_defs_linux_time_offsets *boottime;

    oci_runtime_defs_linux_time_offsets *monotonic;

    yajl_val _residual;
}
oci_runtime_config_linux_time_offsets;

void free_oci_runtime_config_linux_time_offsets (oci_runtime_config_linux_time_offsets *ptr);

oci_runtime_config_linux_time_offsets *make_oci_runtime_config_linux_time_offsets (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux_time_offsets (yajl_gen g, const oci_runtime_config_linux_time_offsets *ptr, const struct parser_context *ctx, parser_error *err);

typedef struct {
    oci_runtime_defs_linux_device **devices;
    size_t devices_len;

    oci_runtime_defs_id_mapping **uid_mappings;
    size_t uid_mappings_len;

    oci_runtime_defs_id_mapping **gid_mappings;
    size_t gid_mappings_len;

    oci_runtime_defs_linux_namespace_reference **namespaces;
    size_t namespaces_len;

    oci_runtime_config_linux_resources *resources;

    char *cgroups_path;

    char *rootfs_propagation;

    oci_runtime_config_linux_seccomp *seccomp;

    json_map_string_string *sysctl;

    char **masked_paths;
    size_t masked_paths_len;

    char **readonly_paths;
    size_t readonly_paths_len;

    char *mount_label;

    oci_runtime_config_linux_intel_rdt *intel_rdt;

    oci_runtime_defs_linux_personality *personality;

    oci_runtime_config_linux_time_offsets *time_offsets;

    yajl_val _residual;
}
oci_runtime_config_linux;

void free_oci_runtime_config_linux (oci_runtime_config_linux *ptr);

oci_runtime_config_linux *make_oci_runtime_config_linux (yajl_val tree, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_oci_runtime_config_linux (yajl_gen g, const oci_runtime_config_linux *ptr, const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

