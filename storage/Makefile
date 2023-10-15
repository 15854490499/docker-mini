CFLAGS = -I$(ROOT)/libocispec -I$(ROOT)/utils -I$(ROOT)/storage -I$(ROOT)/registry -I$(ROOT)/log
all: $(OBJ_DIR)/storage.o $(OBJ_DIR)/layer.o $(OBJ_DIR)/rootfs.o $(OBJ_DIR)/driver.o $(OBJ_DIR)/project_quota.o

$(OBJ_DIR)/storage.o: storage.c
	$(C) -c $< $(CFLAGS) -o $@

$(OBJ_DIR)/layer.o: layer.c
	$(C) -c $< $(CFLAGS) -o $@

$(OBJ_DIR)/rootfs.o: rootfs.c
	$(C) -c $< $(CFLAGS) -o $@

$(OBJ_DIR)/driver.o: driver.c
	$(C) -c $< $(CFLAGS) -o $@

$(OBJ_DIR)/project_quota.o: project_quota.c
	$(C) -c $< $(CFLAGS) -o $@
