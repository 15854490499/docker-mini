CXXFLAGS = -I$(ROOT)/capi -I/sdb/home/sch/grpc/install/include -I$(ROOT)/utils -I$(ROOT)/log
all: $(OBJ_DIR)/container.grpc.pb.cc.o $(OBJ_DIR)/container.pb.cc.o $(OBJ_DIR)/image.grpc.pb.cc.o $(OBJ_DIR)/image.pb.cc.o $(OBJ_DIR)/container_client.o $(OBJ_DIR)/image_client.o $(OBJ_DIR)/grpc_connect.o

$(OBJ_DIR)/container.grpc.pb.cc.o: container.grpc.pb.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ -g

$(OBJ_DIR)/container.pb.cc.o: container.pb.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ -g

$(OBJ_DIR)/image.grpc.pb.cc.o: image.grpc.pb.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ -g

$(OBJ_DIR)/image.pb.cc.o: image.pb.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ -g

$(OBJ_DIR)/container_client.o: container_client.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ -g

$(OBJ_DIR)/image_client.o: image_client.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ -g

$(OBJ_DIR)/grpc_connect.o: grpc_connect.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ -g
