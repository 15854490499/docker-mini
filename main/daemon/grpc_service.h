#ifndef __GRPC_SERVICE_H__
#define __GRPC_SERVICE_H__

#ifdef __cplusplus
extern "C" {
#endif

int grpc_server_init();

void grpc_server_wait();

void grpc_server_shutdown();

#ifdef __cplusplus
}
#endif

#endif
