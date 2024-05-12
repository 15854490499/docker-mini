#include <iostream>
#include <string>
#include <grpcpp/grpcpp.h>

#include "container.grpc.pb.h"
#include "container_client.h"
#include "container_api.h"
#include "client_base.h"

#include "utils.h"

using namespace container;

class ContainerCreate : public ClientBase<ContainerService, ContainerService::Stub, container_create_request, container_create_response> {
public:
	explicit ContainerCreate(void *args) : ClientBase(args) { }

	~ContainerCreate() = default;
	
	int run(const container_create_request *sreq, container_create_response *resp) override {
		grpc::ClientContext context;
		
		if(sreq->id != NULL) {
			req.set_id(sreq->id);
		}

		if(sreq->rootfs != NULL) {
			req.set_rootfs(sreq->rootfs);
		}

		if(sreq->image != NULL) {
			req.set_image(sreq->image);
		}

		if(sreq->container_spec != NULL) {
			req.set_container_spec(sreq->container_spec);
		}

		grpc::Status status = stub_->CreateContainer(&context, req, &reply);
		if(!status.ok()) {
			printf("Failed to execute gRPC : %s\n", status.error_message().c_str());
			return -1;
		}
		
		if(!reply.id().empty()) {
			resp->id = strdup_s(reply.id().c_str());
		}

		if(!reply.errmsg().empty()) {
			printf("recv errmsg \n");
			resp->errmsg = strdup_s(reply.errmsg().c_str());	
		}

		return 0;
	}

private:
	container::CreateRequest req;
	container::CreateReply reply;
};

class ContainerStart : public ClientBase<ContainerService, ContainerService::Stub, container_start_request, container_start_response> {
public:
	explicit ContainerStart(void *args) : ClientBase(args) { }

	~ContainerStart() = default;
	
	int run(const container_start_request *sreq, container_start_response *resp) override {
		grpc::ClientContext context;
		
		if(sreq->id != NULL) {
			req.set_id(sreq->id);
		}
		
		grpc::Status status = stub_->StartContainer(&context, req, &reply);
		if(!status.ok()) {
			printf("Failed to execute gRPC : %s\n", status.error_message().c_str());
			return -1;
		}
	
		if(!reply.id().empty()) {
			resp->id = strdup_s(reply.id().c_str());
		}

		if(!reply.errmsg().empty()) {
			resp->errmsg = strdup_s(reply.errmsg().c_str());	
		}

		return 0;
	}

private:
	container::StartRequest req;
	container::StartReply reply;
};

class ContainerStop : public ClientBase<ContainerService, ContainerService::Stub, container_stop_request, container_stop_response> {
public:
	explicit ContainerStop(void *args) : ClientBase(args) { }

	~ContainerStop() = default;
	
	int run(const container_stop_request *sreq, container_stop_response *resp) override {
		grpc::ClientContext context;
		
		if(sreq->id != NULL) {
			req.set_id(sreq->id);
		}
		
		grpc::Status status = stub_->StopContainer(&context, req, &reply);
		if(!status.ok()) {
			printf("Failed to execute gRPC : %s\n", status.error_message().c_str());
			return -1;
		}
	
		if(!reply.id().empty()) {
			resp->id = strdup_s(reply.id().c_str());
		}

		if(!reply.errmsg().empty()) {
			resp->errmsg = strdup_s(reply.errmsg().c_str());	
		}

		return 0;
	}

private:
	container::StopRequest req;
	container::StopReply reply;
};

class ContainerRemove : public ClientBase<ContainerService, ContainerService::Stub, container_remove_request, container_remove_response> {
public:
	explicit ContainerRemove(void *args) : ClientBase(args) { }

	~ContainerRemove() = default;
	
	int run(const container_remove_request *sreq, container_remove_response *resp) override {
		grpc::ClientContext context;
		
		if(sreq->id != NULL) {
			req.set_id(sreq->id);
		}
		
		grpc::Status status = stub_->RemoveContainer(&context, req, &reply);
		if(!status.ok()) {
			printf("Failed to execute gRPC : %s\n", status.error_message().c_str());
			return -1;
		}
	
		if(!reply.id().empty()) {
			resp->id = strdup_s(reply.id().c_str());
		}

		if(!reply.errmsg().empty()) {
			resp->errmsg = strdup_s(reply.errmsg().c_str());	
		}

		return 0;
	}

private:
	container::RemoveRequest req;
	container::RemoveReply reply;
};

int container_client_ops_init(grpc_connect_ops *ops) {
	if(ops == nullptr) {
		printf("invalid nullptr\n");
		return -1;
	}

	ops->container.create = container_func<container_create_request, container_create_response, ContainerCreate>;
	ops->container.start = container_func<container_start_request, container_start_response, ContainerStart>;
	ops->container.stop = container_func<container_stop_request, container_stop_response, ContainerStop>;
	ops->container.remove = container_func<container_remove_request, container_remove_response, ContainerRemove>;

	return 0;
}
