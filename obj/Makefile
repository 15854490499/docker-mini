LD = -std=c++11
$(BIN_DIR)/$(BIN) : $(OBJ)
	$(CXX) $^ $(LD) -o $@ -lcurl -lhttp_parser -lyajl -lcrypto -lssl -lm -lz -I/usr/local/include -L/usr/local/lib -larchive -lpthread -g
