CFLAGS = -I$(ROOT)/libocispec
all: $(OBJ_DIR)/utils.o $(OBJ_DIR)/fs.o $(OBJ_DIR)/archive.o $(OBJ_DIR)/sha256.o $(OBJ_DIR)/timestamp.o

$(OBJ_DIR)/utils.o: utils.c
	$(C) -c $< -o $@ 

$(OBJ_DIR)/fs.o: fs.c
	$(C) -c $< -o $@

$(OBJ_DIR)/archive.o: archive.c
	$(C) -c $< $(CFLAGS) -o $@

$(OBJ_DIR)/sha256.o: sha256.c
	$(C) -c $< -o $@

$(OBJ_DIR)/timestamp.o: timestamp.c
	$(C) -c $< -o $@
