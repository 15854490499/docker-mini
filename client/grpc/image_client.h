#ifndef __IMAGE_CLIENT_H__
#define __IMAGE_CLIENT_H__

#include "grpc_connect.h"

#ifdef __cplusplus
extern "C" {
#endif

int image_client_ops_init(grpc_connect_ops *ops);

#ifdef __cplusplus
}
#endif

#endif
