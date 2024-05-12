#include "image_api.h"
#include "grpc_image_service.h"
#include "utils.h"
#include "log.h"

int ImageServiceImpl::pull_image_request_from_grpc(const PullImageRequest *grequest, im_pull_request *request) {
	int ret = 0;
	
	if(request == NULL || grequest == NULL) {
		LOG_ERROR("invalid NULL ptr\n");
		ret = -1;
		goto out;
	}

	if(!grequest->image().empty()) {
		request->image = (char*)strdup_s(grequest->image().c_str());
	} else {
		request->image = NULL; 
	}

	request->type = strdup_s(IMAGE_TYPE_OCI);

out:
	return ret;	
}

void ImageServiceImpl::pull_image_response_to_grpc(im_pull_response *response, PullImageReply *reply) {
	if(response == NULL || reply == NULL) {
		LOG_ERROR("invalid NULL ptr\n");
		return;
	}

	if(response->image_ref != NULL) {
		reply->set_image_ref(response->image_ref);
	}

	if(response->errmsg != NULL) {
		reply->set_errmsg(response->errmsg);
	}

	return;
}

Status ImageServiceImpl::PullImage(ServerContext *context, const PullImageRequest *request, PullImageReply *reply) {
	int ret = 0;
	im_pull_request *req { nullptr };
	im_pull_response *resp { nullptr };

	req = (im_pull_request*)common_calloc_s(sizeof(im_pull_request));
	if(req == NULL) {
		LOG_ERROR("memory out");
		reply->set_errmsg("memory out");
		return Status::OK;
	}

	ret = pull_image_request_from_grpc(request, req);
	if(ret != 0) {
		LOG_ERROR("Failed to transform grpc request");
		reply->set_errmsg("error input");
		goto out;
	}

	ret = im_pull_image(req, &resp);
	if(ret != 0) {
		if(resp != NULL && resp->errmsg !=NULL) {
			LOG_ERROR("%s\n", resp->errmsg);
		} else {
			LOG_ERROR("Failed to call pull image");
		}
	}
	
	pull_image_response_to_grpc(resp, reply);

out:
	free_im_pull_request(req);
	free_im_pull_response(resp);
	return Status::OK;
}

int ImageServiceImpl::remove_image_request_from_grpc(const RemoveImageRequest *grequest, im_remove_request *request) {
	int ret = 0;

	if(request == NULL || grequest == NULL) {
		LOG_ERROR("invalid NULL ptr");
		ret = -1;
		goto out;
	}

	if(!grequest->image().empty()) {
		request->image = (char*)strdup_s(grequest->image().c_str());
	} else {
		request->image = NULL; 
	}
	
	request->force = grequest->force();

out:
	return ret;
}

void ImageServiceImpl::remove_image_response_to_grpc(im_remove_response *response, RemoveImageReply *reply) {
	if(response == NULL || reply == NULL) {
		LOG_ERROR("invalid NULL ptr");
		return;
	}
	if(response->errmsg != NULL) {
		reply->set_errmsg(response->errmsg);
	}
	return;
}

Status ImageServiceImpl::RemoveImage(ServerContext *context, const RemoveImageRequest *request, RemoveImageReply *reply) {
	int ret = 0;
	im_remove_request *req { nullptr };
	im_remove_response *resp { nullptr };

	req = (im_remove_request*)common_calloc_s(sizeof(im_remove_request));
	if(req == NULL) {
		LOG_ERROR("memory out");
		reply->set_errmsg("memory out");
		return Status::OK;
	}

	ret = remove_image_request_from_grpc(request, req);
	if(ret != 0) {
		LOG_ERROR("Failed to transform grpc request");
		reply->set_errmsg("error input");
		goto out;
	}

	ret = im_rm_image(req, &resp);
	if(ret != 0) {
		LOG_ERROR("%s", resp->errmsg);
	}
	remove_image_response_to_grpc(resp, reply);
out:
	free_im_remove_request(req);
	free_im_remove_response(resp);
	return Status::OK;	
}
