LD = -std=c++11

ABSL_LIBS = -labsl_random_distributions \
		  -labsl_random_seed_sequences \
		  -labsl_random_internal_pool_urbg \
		  -labsl_random_internal_randen \
		  -labsl_random_internal_randen_hwaes \
		  -labsl_random_internal_randen_hwaes_impl \
		  -labsl_random_internal_randen_slow \
		  -labsl_random_internal_platform \
		  -labsl_random_internal_seed_material \
		  -labsl_random_seed_gen_exception \
		  -laddress_sorting \
		  -labsl_log_internal_check_op \
		  -labsl_leak_check \
		  -labsl_die_if_null \
		  -labsl_log_internal_conditions \
		  -labsl_log_internal_message \
		  -labsl_log_internal_nullguard \
		  -labsl_examine_stack \
		  -labsl_log_internal_format \
		  -labsl_log_internal_proto \
		  -labsl_log_internal_log_sink_set \
		  -labsl_log_sink \
		  -labsl_log_entry \
		  -labsl_log_initialize \
		  -labsl_log_globals \
		  -labsl_vlog_config_internal \
		  -labsl_log_internal_fnmatch \
		  -labsl_log_internal_globals \
		  -labsl_statusor \
		  -labsl_status \
		  -labsl_strerror \
		  -lutf8_validity \
		  -labsl_flags_usage \
		  -labsl_flags_usage_internal \
		  -labsl_flags_internal \
		  -labsl_flags_marshalling \
		  -labsl_flags_reflection \
		  -labsl_flags_config

UPB_LIBS = -lupb_json_lib \
		   -lupb_textformat_lib \
		   -lupb_message_lib \
		   -lupb_base_lib \
		   -lupb_mem_lib

GRPC_LIBS = -lgrpc++_reflection \
			-lgrpcpp_channelz \
			-lgrpc_authorization_provider 

all: $(BIN_DIR)/$(CLIENT_BIN) $(BIN_DIR)/$(DAEMON_BIN)

$(BIN_DIR)/$(CLIENT_BIN) : $(CLIENT_OBJ)
	$(CXX) $^ $(LD) -o $@ -I/usr/local/include \
						  -L$(GRPC_PATH) \
						  -L/lib/x86_64-linux-gnu \
						  -L/usr/local/lib \
						  `pkg-config --cflags --libs --static protobuf protobuf-lite grpc grpc++ gpr grpc_unsecure grpc++_unsecure absl_flags absl_flags_parse` \
						  $(ABSL_LIBS) \
						  -lutf8_range_lib \
						  -lre2 \
						  $(UPB_LIBS) \
						  -lsystemd \
						  -lyajl \
						  -lcrypto \
						  -lssl \
						  -lm \
						  -lz \
						  -lpthread \
						  -llxc \
						  $(GRPC_LIBS) \
						  -g

$(BIN_DIR)/$(DAEMON_BIN) : $(DAEMON_OBJ)
	$(CXX) $^ $(LD) -o $@ -I/usr/local/include \
						  -L$(GRPC_PATH) \
						  -L$(LXC_PATH) \
						  -L/lib/x86_64-linux-gnu \
						  -L/usr/local/lib \
						  -lcurl \
						  -lhttp_parser \
						  -larchive \
						  `pkg-config --cflags --libs --static protobuf protobuf-lite grpc grpc++ gpr grpc_unsecure grpc++_unsecure absl_flags absl_flags_parse` \
						  $(ABSL_LIBS) \
						  -lutf8_range_lib \
						  -lre2 \
						  $(UPB_LIBS) \
						  -lsystemd \
						  -lyajl \
						  -lcrypto \
						  -lssl \
						  -lm \
						  -lz \
						  -lpthread \
						  -llxc \
						  $(GRPC_LIBS) \
						  -g
