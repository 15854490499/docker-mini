CFLAGS = -I$(ROOT)/log
all: $(OBJ_DIR)/network.o $(OBJ_DIR)/nl.o 

$(OBJ_DIR)/network.o: network.c
	$(C) -c $< $(CFLAGS) -o $@

$(OBJ_DIR)/nl.o: nl.c
	$(C) -c $< $(CFLAGS) -o $@
