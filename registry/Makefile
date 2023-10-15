CFLAGS = -I$(ROOT)/libocispec -I$(ROOT)/utils -I$(ROOT)/configs -I$(ROOT)/http -I$(ROOT)/storage -I$(ROOT)/log
$(OBJ_DIR)/registry.o: registry.c ../configs/config.c
	$(C) -c $< $(CFLAGS) -o $@ -g
