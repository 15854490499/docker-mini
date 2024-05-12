CXXFLAGS = -I$(ROOT)/libocispec -I$(ROOT)/utils -I$(ROOT)/net -I$(ROOT)/capi -I$(ROOT)/log -I$(ROOT)/client/grpc -I/sdb/home/sch/grpc/install/include
all: $(OBJ_DIR)/daemon_main.o $(OBJ_DIR)/service_common.o $(OBJ_DIR)/grpc_service.o $(OBJ_DIR)/grpc_image_service.o $(OBJ_DIR)/grpc_container_service.o

$(OBJ_DIR)/daemon_main.o: main.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ -g

$(OBJ_DIR)/service_common.o: service_common.cc
	$(CXX) -c $< $(CXXFLAGS) -D DAEMON_COMPILE -o $@ -g

$(OBJ_DIR)/grpc_service.o: grpc_service.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ -g

$(OBJ_DIR)/grpc_image_service.o: grpc_image_service.cc
	$(CXX) -c $< $(CXXFLAGS) -D DAEMON_COMPILE -o $@ -g

$(OBJ_DIR)/grpc_container_service.o: grpc_container_service.cc
	$(CXX) -c $< $(CXXFLAGS) -D DAEMON_COMPILE -o $@ -g
