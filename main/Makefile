CXXFLAGS = -I$(ROOT)/libocispec -I$(ROOT)/utils -I$(ROOT)/net -I$(ROOT)/capi
all: $(OBJ_DIR)/docker.o $(OBJ_DIR)/main.o $(OBJ_DIR)/parse_cmd.o

$(OBJ_DIR)/docker.o: docker.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@ 

$(OBJ_DIR)/main.o: main.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@

$(OBJ_DIR)/parse_cmd.o: parse_cmd.cc
	$(CXX) -c $< $(CXXFLAGS) -o $@
