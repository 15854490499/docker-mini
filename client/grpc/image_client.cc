#include <iostream>
#include <string>
#include <grpcpp/grpcpp.h>

#include "image.grpc.pb.h"
#include "image_client.h"
#include "image_api.h"
#include "client_base.h"

#include "utils.h"
#include "log.h"

using namespace image;

class ImagePull : public ClientBase<ImageService, ImageService::Stub, im_pull_request, im_pull_response> {
public:
	explicit ImagePull(void *args) : ClientBase(args) { }

	~ImagePull() = default;
	
	int run(const im_pull_request *sreq, im_pull_response *resp) override {
		grpc::ClientContext context;
		
		if(sreq->image != NULL) {
			req.set_image(sreq->image);
		}

		grpc::Status status = stub_->PullImage(&context, req, &reply);
		if(!status.ok()) {
			printf("Failed to execute gRPC : %s\n", status.error_message().c_str());
			return -1;
		}
		
		if(!reply.image_ref().empty()) {
			resp->image_ref = strdup_s(reply.image_ref().c_str());
		}

		if(!reply.errmsg().empty()) {
			resp->errmsg = strdup_s(reply.errmsg().c_str());	
		}

		return 0;
	}

private:
	image::PullImageRequest req;
	image::PullImageReply reply;
};

class ImageRemove : public ClientBase<ImageService, ImageService::Stub, im_remove_request, im_remove_response> {
public:
	explicit ImageRemove(void *args) : ClientBase(args) { }

	~ImageRemove() = default;
	
	int run(const im_remove_request *sreq, im_remove_response *resp) override {
		grpc::ClientContext context;
		
		if(sreq->image != NULL) {
			req.set_image(sreq->image);
		}

		grpc::Status status = stub_->RemoveImage(&context, req, &reply);
		if(!status.ok()) {
			printf("Failed to execute gRPC : %s\n", status.error_message().c_str());
			return -1;
		}
		
		if(!reply.errmsg().empty()) {
			resp->errmsg = strdup_s(reply.errmsg().c_str());	
		}

		return 0;
	}

private:
	image::RemoveImageRequest req;
	image::RemoveImageReply reply;
};

int image_client_ops_init(grpc_connect_ops *ops) {
	if(ops == nullptr) {
		printf("invalid nullptr\n");
		return -1;
	}

	ops->image.pull = container_func<im_pull_request, im_pull_response, ImagePull>;
	ops->image.remove = container_func<im_remove_request, im_remove_response, ImageRemove>;

	return 0;
}
