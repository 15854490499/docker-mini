#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>

#include "af_unix.h"
#include "log.h"

int abstract_unix_rcv_credential(int fd, void *data, size_t size)
{
    struct msghdr msg = {0};
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct ucred cred;
    int ret;
    char cmsgbuf[CMSG_SPACE(sizeof(cred))] = {0};
    char buf[1] = {0};

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    iov.iov_base = data ? data : buf;
    iov.iov_len = data ? size : sizeof(buf);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(fd, &msg, 0); 
    if (ret <= 0)
        return ret;

    cmsg = CMSG_FIRSTHDR(&msg);

    if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
        cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_CREDENTIALS) {
        memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));

        if (cred.uid && (cred.uid != getuid() || cred.gid != getgid()))
            return syserror_set(-EACCES, "Message denied for '%d/%d'", cred.uid, cred.gid);
    }   

    return ret;
}

static int abstract_unix_recv_fds_iov(int fd, struct unix_fds *ret_fds, struct iovec *ret_iov, size_t size_ret_iov)
{
    __do_free char *cmsgbuf = NULL;
    int ret = 0;
    struct msghdr msg = { 0x00 };
    struct cmsghdr *cmsg = NULL;
    size_t cmsgbufsize = CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(ret_fds->fd_count_max * sizeof(int));

    if(ret_fds->flags & ~UNIX_FDS_ACCEPT_MASK)
        return EINVAL;

    if(hweight32((ret_fds->flags & ~UNIX_FDS_ACCEPT_NONE)) > 1)
        return EINVAL;

    if(ret_fds->fd_count_max >= KERNEL_SCM_MAX_FD)
        return EINVAL;

    if(ret_fds->fd_count_ret != 0)
        return EINVAL;

    cmsgbuf = zalloc(cmsgbufsize);
    if (!cmsgbuf)
        return ENOMEM;

    msg.msg_control     = cmsgbuf;
    msg.msg_controllen  = cmsgbufsize;

    msg.msg_iov = ret_iov;
    msg.msg_iovlen  = size_ret_iov;

again:
    ret = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
    if (ret < 0) {
        if (errno == EINTR)
            goto again;
        LOG_ERROR("Failed to receive response");
		return -1;
    }
    if (ret == 0) {
        return 0;
	}

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            __u32 idx;
    
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
            int *fds_raw = (int *)CMSG_DATA(cmsg);
#pragma GCC diagnostic pop
            __u32 num_raw = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

            if (num_raw >= KERNEL_SCM_MAX_FD) {
                for (idx = 0; idx < num_raw; idx++)
                    close(fds_raw[idx]);
				LOG_ERROR("Received excessive number of file descriptors");
                return -EFBIG;
            }

            if (msg.msg_flags & MSG_CTRUNC) {
                for (idx = 0; idx < num_raw; idx++)
                    close(fds_raw[idx]);
				LOG_ERROR("Control message was truncated; closing all fds and rejecting incomplete message");
                return -EFBIG;
            }
            if (ret_fds->fd_count_max > num_raw) {
                if (!(ret_fds->flags & UNIX_FDS_ACCEPT_LESS)) {
                    for (idx = 0; idx < num_raw; idx++)
                        close(fds_raw[idx]);
					LOG_ERROR("Received fewer file descriptors than we expected %u != %u", ret_fds->fd_count_max, num_raw);
                    return -EINVAL;
                }

                for (idx = num_raw; idx < ret_fds->fd_count_max; idx++)
                    ret_fds->fd[idx] = -EBADF;

                ret_fds->flags |= UNIX_FDS_RECEIVED_LESS;
            } else if (ret_fds->fd_count_max < num_raw) {
                if (!(ret_fds->flags & UNIX_FDS_ACCEPT_MORE)) {
                    for (idx = 0; idx < num_raw; idx++)
                        close(fds_raw[idx]);
					LOG_ERROR("Received more file descriptors than we expected %u != %u", ret_fds->fd_count_max, num_raw);
                    return -EINVAL;
                }

                for (idx = ret_fds->fd_count_max; idx < num_raw; idx++)
                    close(fds_raw[idx]);

                num_raw = ret_fds->fd_count_max;
                ret_fds->flags |= UNIX_FDS_RECEIVED_MORE;
            } else {
                ret_fds->flags |= UNIX_FDS_RECEIVED_EXACT;
            }

            if (hweight32((ret_fds->flags & ~UNIX_FDS_ACCEPT_MASK)) > 1) {
                for (idx = 0; idx < num_raw; idx++)
                    close(fds_raw[idx]);
				LOG_ERROR("Invalid flag combination; closing to not risk leaking fds %u != %u", ret_fds->fd_count_max, num_raw);
                return -EINVAL;
            }

            memcpy(ret_fds->fd, CMSG_DATA(cmsg), num_raw * sizeof(int));
            ret_fds->fd_count_ret = num_raw;
            break;
        }
    }

    if (ret_fds->fd_count_ret == 0) {
        ret_fds->flags |= UNIX_FDS_RECEIVED_NONE;
        if ((ret_fds->flags & UNIX_FDS_ACCEPT_MASK) && !(ret_fds->flags & UNIX_FDS_ACCEPT_NONE)) {
            LOG_ERROR("Received no file descriptors");
			return -EINVAL; 
		}
    }

    return ret;
}

int abstract_unix_recv_one_fd(int fd, int *ret_fd, void *ret_data, size_t size_ret_data) {
	call_cleaner(put_unix_fds) struct unix_fds *fds = NULL;
	char buf[1] = {};
    struct iovec iov = { 
        .iov_base   = ret_data ? ret_data : buf,
        .iov_len    = ret_data ? size_ret_data : sizeof(buf),
    };  
    int ret;

    fds = &(struct unix_fds){
        .fd_count_max = 1,
    };  

    ret = abstract_unix_recv_fds_iov(fd, fds, &iov, 1); 
    if (ret < 0)
        return ret;

    if (ret == 0)
        return ENODATA;

    if (fds->fd_count_ret != fds->fd_count_max)
        *ret_fd = -EBADF;
    else
        *ret_fd = move_fd(fds->fd[0]);

    return ret;
}

static int abstract_unix_send_fds_iov(int fd, const int *sendfds, int num_sendfds, struct iovec *const iov, size_t iovlen)
{
    __do_free char *cmsgbuf = NULL;
    int ret = 0;
    struct msghdr msg = { 0x00 };
    struct cmsghdr *cmsg = NULL;
    size_t cmsgbufsize = CMSG_SPACE(num_sendfds * sizeof(int));

    if (num_sendfds <= 0)
        return ret_errno(EINVAL);

    cmsgbuf = malloc(cmsgbufsize);
    if (!cmsgbuf)
        return ret_errno(-ENOMEM);

    msg.msg_control = cmsgbuf;
    msg.msg_controllen = cmsgbufsize;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(num_sendfds * sizeof(int));

    msg.msg_controllen = cmsg->cmsg_len;

    memcpy(CMSG_DATA(cmsg), sendfds, num_sendfds * sizeof(int));

    msg.msg_iov = iov;
    msg.msg_iovlen = iovlen;

    do {
        ret = sendmsg(fd, &msg, MSG_NOSIGNAL);
    } while(ret < 0 && errno == EINTR);

    return ret;
}

int abstract_unix_send_fds(int fd, const int *sendfds, int num_sendfds, void *data, size_t size)
{
    char buf[1] = { 0x00 }; 
    struct iovec iov = { 
        .iov_base   = data ? data : buf,
        .iov_len    = data ? size : sizeof(buf),
    };  
    return abstract_unix_send_fds_iov(fd, sendfds, num_sendfds, &iov, 1); 
}

