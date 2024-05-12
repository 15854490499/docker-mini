#ifndef CLIENT_GRPC_CLIENT_BASE_H
#define CLIENT_GRPC_CLIENT_BASE_H

#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <string>

#include "utils.h"

template <class SV, class sTB, class RQ, class RP>
class ClientBase {
public:
	explicit ClientBase(void *args) {
		auto *arguments = reinterpret_cast<client_connect_config*>(args);
		std::string socket_addr = arguments->socket;
		
		stub_ = SV::NewStub(grpc::CreateChannel(socket_addr, grpc::InsecureChannelCredentials()));
	}
	
	virtual ~ClientBase() = default;
	
	virtual int run(const RQ *sreq, RP *resp) = 0;

protected:
	std::unique_ptr<sTB> stub_;
};

template <class REQUEST, class RESPONSE, class FUNC>
auto container_func(const REQUEST *request, RESPONSE *response, void *arg) noexcept -> int {
	if(request == nullptr || response == nullptr || arg == nullptr) {
		printf("Receive NULL args\n");
		return -1;
	}

	std::unique_ptr<FUNC> client(new (std::nothrow) FUNC(arg));
	if(client == nullptr) {
		printf("Out of memory\n");
		return -1;
	}

	return client->run(request, response);
}

#endif
