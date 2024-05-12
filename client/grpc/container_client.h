#ifndef __CONTAINER_CLIENT_H__
#define __CONTAINER_CLIENT_H__

#include "grpc_connect.h"

#ifdef __cplusplus
extern "C" {
#endif

int container_client_ops_init(grpc_connect_ops *ops);

#ifdef __cplusplus
}
#endif

#endif

