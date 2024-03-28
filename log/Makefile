CFLAGS = -I$(ROOT)/utils
all: $(OBJ_DIR)/asynclog.o $(OBJ_DIR)/client_asynclog.o $(OBJ_DIR)/log.o

$(OBJ_DIR)/client_asynclog.o: asynclog.c
	$(C) -c $< $(CFLAGS) -o $@ -g

$(OBJ_DIR)/asynclog.o: asynclog.c
	$(C) -c $< $(CFLAGS) -D DAEMON_COMPILE -o $@ -g

$(OBJ_DIR)/log.o: log.c 
	$(C) -c $< $(CFLAGS) -o $@ -g
