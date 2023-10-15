CFLAGS = -I$(ROOT)/libocispec -I$(ROOT)/utils -I$(ROOT)/registry -I$(ROOT)/storage -I$(ROOT)/log
all: $(OBJ_DIR)/image_api.o $(OBJ_DIR)/container_api.o 

$(OBJ_DIR)/image_api.o: image_api.c 
	$(C) -c $< $(CFLAGS) -o $@

$(OBJ_DIR)/container_api.o: container_api.c 	
	$(C) -c $< $(CFLAGS) -o $@

