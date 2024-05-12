#ifndef __GRPC_IMAGE_SERVICE_H__
#define __GRPC_IMAGE_SERVICE_H__

#include <grpc++/grpc++.h>

#include "image.grpc.pb.h"
#include "image_api.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using namespace image;

class ImageServiceImpl final : public ImageService::Service {
public:
	ImageServiceImpl() = default;
	virtual ~ImageServiceImpl() = default;

	Status PullImage(ServerContext *context, const PullImageRequest *request, PullImageReply *reply) override;

	Status RemoveImage(ServerContext *context, const RemoveImageRequest *request, RemoveImageReply *reply) override;
private:
	int pull_image_request_from_grpc(const PullImageRequest *grequest, im_pull_request *request);

	void pull_image_response_to_grpc(im_pull_response *response, PullImageReply *reply);

	int remove_image_request_from_grpc(const RemoveImageRequest *grequest, im_remove_request *request);

	void remove_image_response_to_grpc(im_remove_response *response, RemoveImageReply *reply);
};


#endif
