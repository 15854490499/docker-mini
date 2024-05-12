// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: image.proto

#include "image.pb.h"
#include "image.grpc.pb.h"

#include <functional>
#include <grpcpp/support/async_stream.h>
#include <grpcpp/support/async_unary_call.h>
#include <grpcpp/impl/channel_interface.h>
#include <grpcpp/impl/client_unary_call.h>
#include <grpcpp/support/client_callback.h>
#include <grpcpp/support/message_allocator.h>
#include <grpcpp/support/method_handler.h>
#include <grpcpp/impl/rpc_service_method.h>
#include <grpcpp/support/server_callback.h>
#include <grpcpp/impl/server_callback_handlers.h>
#include <grpcpp/server_context.h>
#include <grpcpp/impl/service_type.h>
#include <grpcpp/support/sync_stream.h>
namespace image {

static const char* ImageService_method_names[] = {
  "/image.ImageService/PullImage",
  "/image.ImageService/RemoveImage",
};

std::unique_ptr< ImageService::Stub> ImageService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< ImageService::Stub> stub(new ImageService::Stub(channel, options));
  return stub;
}

ImageService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options)
  : channel_(channel), rpcmethod_PullImage_(ImageService_method_names[0], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_RemoveImage_(ImageService_method_names[1], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status ImageService::Stub::PullImage(::grpc::ClientContext* context, const ::image::PullImageRequest& request, ::image::PullImageReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::image::PullImageRequest, ::image::PullImageReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_PullImage_, context, request, response);
}

void ImageService::Stub::async::PullImage(::grpc::ClientContext* context, const ::image::PullImageRequest* request, ::image::PullImageReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::image::PullImageRequest, ::image::PullImageReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_PullImage_, context, request, response, std::move(f));
}

void ImageService::Stub::async::PullImage(::grpc::ClientContext* context, const ::image::PullImageRequest* request, ::image::PullImageReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_PullImage_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::image::PullImageReply>* ImageService::Stub::PrepareAsyncPullImageRaw(::grpc::ClientContext* context, const ::image::PullImageRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::image::PullImageReply, ::image::PullImageRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_PullImage_, context, request);
}

::grpc::ClientAsyncResponseReader< ::image::PullImageReply>* ImageService::Stub::AsyncPullImageRaw(::grpc::ClientContext* context, const ::image::PullImageRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncPullImageRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ImageService::Stub::RemoveImage(::grpc::ClientContext* context, const ::image::RemoveImageRequest& request, ::image::RemoveImageReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::image::RemoveImageRequest, ::image::RemoveImageReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_RemoveImage_, context, request, response);
}

void ImageService::Stub::async::RemoveImage(::grpc::ClientContext* context, const ::image::RemoveImageRequest* request, ::image::RemoveImageReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::image::RemoveImageRequest, ::image::RemoveImageReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_RemoveImage_, context, request, response, std::move(f));
}

void ImageService::Stub::async::RemoveImage(::grpc::ClientContext* context, const ::image::RemoveImageRequest* request, ::image::RemoveImageReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_RemoveImage_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::image::RemoveImageReply>* ImageService::Stub::PrepareAsyncRemoveImageRaw(::grpc::ClientContext* context, const ::image::RemoveImageRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::image::RemoveImageReply, ::image::RemoveImageRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_RemoveImage_, context, request);
}

::grpc::ClientAsyncResponseReader< ::image::RemoveImageReply>* ImageService::Stub::AsyncRemoveImageRaw(::grpc::ClientContext* context, const ::image::RemoveImageRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncRemoveImageRaw(context, request, cq);
  result->StartCall();
  return result;
}

ImageService::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ImageService_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ImageService::Service, ::image::PullImageRequest, ::image::PullImageReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ImageService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::image::PullImageRequest* req,
             ::image::PullImageReply* resp) {
               return service->PullImage(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ImageService_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ImageService::Service, ::image::RemoveImageRequest, ::image::RemoveImageReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ImageService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::image::RemoveImageRequest* req,
             ::image::RemoveImageReply* resp) {
               return service->RemoveImage(ctx, req, resp);
             }, this)));
}

ImageService::Service::~Service() {
}

::grpc::Status ImageService::Service::PullImage(::grpc::ServerContext* context, const ::image::PullImageRequest* request, ::image::PullImageReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ImageService::Service::RemoveImage(::grpc::ServerContext* context, const ::image::RemoveImageRequest* request, ::image::RemoveImageReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace image
