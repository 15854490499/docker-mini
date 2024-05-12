#ifndef __AF_UNIX_H__
#define __AF_UNIX_H__

#include <stdio.h>
#include <sys/socket.h>
#include <stddef.h>
#include <sys/un.h>

#include "container_utils.h"

#define KERNEL_SCM_MAX_FD 253

#define UNIX_FDS_ACCEPT_EXACT ((__u32)(1 << 0)) 

#define UNIX_FDS_ACCEPT_LESS ((__u32)(1 << 1))

#define UNIX_FDS_ACCEPT_MORE ((__u32)(1 << 2))

#define UNIX_FDS_ACCEPT_NONE ((__u32)(1 << 3))

#define UNIX_FDS_ACCEPT_MASK (UNIX_FDS_ACCEPT_EXACT | UNIX_FDS_ACCEPT_LESS | UNIX_FDS_ACCEPT_MORE | UNIX_FDS_ACCEPT_NONE)

#define UNIX_FDS_RECEIVED_EXACT ((__u32)(1 << 16))

#define UNIX_FDS_RECEIVED_LESS ((__u32)(1 << 17))

#define UNIX_FDS_RECEIVED_MORE ((__u32)(1 << 18))

#define UNIX_FDS_RECEIVED_NONE ((__u32)(1 << 19))

struct unix_fds {
    __u32 fd_count_max;
    __u32 fd_count_ret;
    __u32 flags;
    __s32 fd[KERNEL_SCM_MAX_FD];
} __attribute__((aligned(8)));

static inline void put_unix_fds(struct unix_fds *fds)
{
    if (fds != NULL) {
        for (size_t idx = 0; idx < fds->fd_count_ret; idx++)
            close_prot_errno_disarm(fds->fd[idx]);
    }
}

int abstract_unix_rcv_credential(int fd, void *data, size_t size);
int abstract_unix_recv_one_fd(int fd, int *ret_fd, void *ret_data, size_t size_ret_data);
int abstract_unix_send_fds(int fd, const int *sendfds, int num_sendfds, void *data, size_t size);

#endif
