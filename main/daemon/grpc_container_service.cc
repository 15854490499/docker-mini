#include "container_api.h"
#include "grpc_container_service.h"
#include "utils.h"
#include "log.h"

int ContainerServiceImpl::container_create_request_from_grpc(const CreateRequest *grequest, container_create_request *request) {
	int ret = 0;
	
	if(request == NULL || grequest == NULL) {
		LOG_ERROR("invalid NULL ptr\n");
		ret = -1;
		goto out;
	}

	if(!grequest->id().empty()) {
		request->id = (char*)strdup_s(grequest->id().c_str());
	} else {
		request->id = NULL; 
	}
	if(!grequest->image().empty()) {
		request->image = (char*)strdup_s(grequest->image().c_str());
	} else {
		request->image = NULL;
	}
	if(!grequest->rootfs().empty()) {
		request->rootfs = (char*)strdup_s(grequest->rootfs().c_str());
	} else {
		request->rootfs = NULL;
	}
	if(!grequest->container_spec().empty()) {
		request->container_spec = (char*)strdup_s(grequest->container_spec().c_str());
	} else {
		request->container_spec = NULL;
	}

out:
	return ret;
}

void ContainerServiceImpl::container_create_response_to_grpc(container_create_response *response, CreateReply *reply) {
	if(response == NULL || reply == NULL) {
		LOG_ERROR("invalid NULL ptr\n");
		return;
	}

	if(response->id != NULL) {
		reply->set_id(response->id);
	}

	if(response->errmsg != NULL) {
		reply->set_errmsg(response->errmsg);
	}

	return;
}

Status ContainerServiceImpl::CreateContainer(ServerContext *context, const CreateRequest *request, CreateReply *reply) {
	int ret = 0;
	container_create_request *req { nullptr };
	container_create_response *resp = { nullptr };

	req = (container_create_request*)common_calloc_s(sizeof(container_create_request));
	if(req == NULL) {
		LOG_ERROR("memory out\n");
		reply->set_errmsg("memory out");
		return Status::OK;
	}

	ret = container_create_request_from_grpc(request, req);
	if(ret != 0) {
		LOG_ERROR("Failed to transform grpc request");
		reply->set_errmsg("error input");
		goto out;
	}
		
	ret = container_create(req, &resp);

	if(ret != 0 && resp->errmsg != NULL) {
		LOG_ERROR("%s", resp->errmsg);		
	}
	
	container_create_response_to_grpc(resp, reply);

out:
	free_container_create_request(req);
	free_container_create_response(resp);
	return Status::OK;
}

int ContainerServiceImpl::container_start_request_from_grpc(const StartRequest *grequest, container_start_request *request) {
	int ret = 0;
	
	if(request == NULL || grequest == NULL) {
		LOG_ERROR("invalid NULL ptr");
		ret = -1;
		goto out;
	}

	if(!grequest->id().empty()) {
		request->id = (char*)strdup_s(grequest->id().c_str());
	} else {
		request->id = NULL; 
	}

out:
	return ret;
}

void ContainerServiceImpl::container_start_response_to_grpc(container_start_response *response, StartReply *reply) {
	if(response == NULL || reply == NULL) {
		LOG_ERROR("invalid NULL ptr");
		return;
	}

	if(response->id != NULL) {
		reply->set_id(response->id);
	}

	if(response->errmsg != NULL) {
		reply->set_errmsg(response->errmsg);
	}

	return;
}

Status ContainerServiceImpl::StartContainer(ServerContext *context, const StartRequest *request, StartReply *reply) {
	int ret = 0;
	container_start_request *req { nullptr };
	container_start_response *resp { nullptr };

	req = (container_start_request*)common_calloc_s(sizeof(container_start_request));
	if(req == NULL) {
		LOG_ERROR("memory out");
		reply->set_errmsg("memory out");
		return Status::OK;
	}

	ret = container_start_request_from_grpc(request, req);
	if(ret != 0) {
		LOG_ERROR("Failed to transform grpc request");
		reply->set_errmsg("error input");
		goto out;
	}
	
	ret = container_start(req, &resp);
	if(ret != 0 && resp->errmsg != NULL) {
		LOG_ERROR("%s", resp->errmsg);		
	}

	container_start_response_to_grpc(resp, reply);

out:
	return Status::OK;
}

int ContainerServiceImpl::container_stop_request_from_grpc(const StopRequest *grequest, container_stop_request *request) {
	int ret = 0;

	if(request == NULL || grequest == NULL) {
		LOG_ERROR("invalid NULL ptr");
		ret = -1;
		goto out;
	}

	if(!grequest->id().empty()) {
		request->id = (char*)strdup_s(grequest->id().c_str());
	} else {
		request->id = NULL; 
	}

out:
	return ret;

}

void ContainerServiceImpl::container_stop_response_to_grpc(container_stop_response *response, StopReply *reply) {
	if(response == NULL || reply == NULL) {
		LOG_ERROR("invalid NULL ptr\n");
		return;
	}

	if(response->id != NULL) {
		reply->set_id(response->id);
	}

	if(response->errmsg != NULL) {
		reply->set_errmsg(response->errmsg);
	}

	return;
}

Status ContainerServiceImpl::StopContainer(ServerContext *context, const StopRequest *request, StopReply *reply) {
	int ret = 0;
	container_stop_request *req { nullptr };
	container_stop_response *resp { nullptr };

	req = (container_stop_request*)common_calloc_s(sizeof(container_stop_request));
	if(req == NULL) {
		LOG_ERROR("memory out");
		reply->set_errmsg("memory out");
		return Status::OK;
	}

	ret = container_stop_request_from_grpc(request, req);
	if(ret != 0) {
		LOG_ERROR("Failed to transform grpc request\n");
		reply->set_errmsg("error input");
		goto out;
	}

	ret = container_stop(req, &resp);
	if(ret != 0 && resp->errmsg != NULL) {
		LOG_ERROR("%s", resp->errmsg);
	}

	container_stop_response_to_grpc(resp, reply);

out:
	free_container_stop_request(req);
	free_container_stop_response(resp);
	return Status::OK;
}

int ContainerServiceImpl::container_remove_request_from_grpc(const RemoveRequest *grequest, container_remove_request *request) {
	int ret = 0;
	
	if(request == NULL || grequest == NULL) {
		LOG_ERROR("invalid NULL ptr");
		ret = -1;
		goto out;
	}

	if(!grequest->id().empty()) {
		request->id = (char*)strdup_s(grequest->id().c_str());
	} else {
		request->id = NULL; 
	}

	request->force = grequest->force();

out:
	return ret;
}

void ContainerServiceImpl::container_remove_response_to_grpc(container_remove_response *response, RemoveReply *reply) {
	if(response == NULL || reply == NULL) {
		LOG_ERROR("invalid NULL ptr\n");
		return;
	}

	if(response->id != NULL) {
		reply->set_id(response->id);
	}

	if(response->errmsg != NULL) {
		reply->set_errmsg(response->errmsg);
	}

	reply->set_exit_status(response->exit_status);

	return;
}

Status ContainerServiceImpl::RemoveContainer(ServerContext *context, const RemoveRequest *request, RemoveReply *reply) {
	int ret = 0;
	container_remove_request *req { nullptr };
	container_remove_response *resp { nullptr };

	req = (container_remove_request*)common_calloc_s(sizeof(container_remove_request));
	if(req == NULL) {
		LOG_ERROR("memory out");
		reply->set_errmsg("memory out");
		return Status::OK;
	}

	ret = container_remove_request_from_grpc(request, req);
	if(ret != 0) {
		LOG_ERROR("Failed to transform grpc request\n");
		reply->set_errmsg("error input");
		goto out;
	}

	ret = container_remove(req, &resp);
	if(ret != 0 && resp->errmsg != NULL) {
		LOG_ERROR("%s", resp->errmsg);		
	}

	container_remove_response_to_grpc(resp, reply);

out:
	free_container_remove_request(req);
	free_container_remove_response(resp);
	return Status::OK;
}
