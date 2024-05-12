#include <iostream>
#include <memory>
#include <string>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_format.h"
#include "grpc_service.h"
#include "grpc_image_service.h"
#include "grpc_container_service.h"
#include "log.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

ABSL_FLAG(uint16_t, port, 50051, "Server port for the service");

class GRPCServerImpl {
public:
	explicit GRPCServerImpl() { }
	virtual ~GRPCServerImpl() = default;

	int Init() {
		unsigned short port = absl::GetFlag(FLAGS_port);
		std::string server_address = absl::StrFormat("0.0.0.0:%d", port);
		
		LOG_INFO("daemon starting listening on %s", server_address.c_str());
		
		m_builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
		m_builder.RegisterService(&m_containerService);
		m_builder.RegisterService(&m_imageService);
		m_server = m_builder.BuildAndStart();
		if(m_server == nullptr) {
			LOG_ERROR("Failed to build and start grpc m_server");
			return -1;
		}
		return 0;
	}
	
	void Wait() {
		m_server->Wait();
	}

	void Shutdown() {
		m_server->Shutdown();
	}
private:
	ContainerServiceImpl m_containerService;
	ImageServiceImpl m_imageService;
	ServerBuilder m_builder;
	std::unique_ptr<Server> m_server;
};

GRPCServerImpl *g_grpcserver { nullptr };

int grpc_server_init()
{

    if(g_grpcserver != nullptr) {
        return 0;
    }

    g_grpcserver = new (std::nothrow) GRPCServerImpl();
    if (g_grpcserver == nullptr) {
        return -1;
    }
    if(g_grpcserver->Init() != 0) {
        return -1;
    }

    return 0;
}

void grpc_server_wait()
{
    g_grpcserver->Wait();
}

void grpc_server_shutdown()
{
    g_grpcserver->Shutdown();
}
