#ifndef __GRPC_CONTAINER_SERVICE_H__
#define __GRPC_CONTAINER_SERVICE_H__

#include <grpc++/grpc++.h>

#include "container.grpc.pb.h"
#include "container_api.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using namespace container;

class ContainerServiceImpl final : public ContainerService::Service {
public:
	ContainerServiceImpl() = default;
	virtual ~ContainerServiceImpl() = default;

	Status CreateContainer(ServerContext *context, const CreateRequest *request, CreateReply *reply) override;

	Status StartContainer(ServerContext *context, const StartRequest *request, StartReply *reply) override;
	
	Status StopContainer(ServerContext *context, const StopRequest *request, StopReply *reply) override;
	
	Status RemoveContainer(ServerContext *context, const RemoveRequest *request, RemoveReply *reply) override;
private:
	int container_create_request_from_grpc(const CreateRequest *grequest, container_create_request *request);

	void container_create_response_to_grpc(container_create_response *response, CreateReply *reply);

	int container_start_request_from_grpc(const StartRequest *grequest, container_start_request *request);

	void container_start_response_to_grpc(container_start_response *response, StartReply *reply);

	int container_stop_request_from_grpc(const StopRequest *grequest, container_stop_request *request);

	void container_stop_response_to_grpc(container_stop_response *response, StopReply *reply);

	int container_remove_request_from_grpc(const RemoveRequest *grequest, container_remove_request *request);

	void container_remove_response_to_grpc(container_remove_response *response, RemoveReply *reply);
};


#endif
