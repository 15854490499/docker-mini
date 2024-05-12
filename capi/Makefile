CFLAGS = -I$(ROOT)/libocispec -I$(ROOT)/utils -I$(ROOT)/registry -I$(ROOT)/storage -I$(ROOT)/log -I$(ROOT)/lxcapi
all: $(OBJ_DIR)/image_api.o $(OBJ_DIR)/container_api.o $(OBJ_DIR)/client_image_api.o $(OBJ_DIR)/client_container_api.o 

$(OBJ_DIR)/image_api.o: image_api.c image_api.h
	$(C) -c $< $(CFLAGS) -D DAEMON_COMPILE -o $@

$(OBJ_DIR)/container_api.o: container_api.c container_api.h	
	$(C) -c $< $(CFLAGS) -D DAEMON_COMPILE -o $@

$(OBJ_DIR)/client_image_api.o: image_api.c 
	$(C) -c $< $(CFLAGS) -o $@

$(OBJ_DIR)/client_container_api.o: container_api.c 	
	$(C) -c $< $(CFLAGS) -o $@
