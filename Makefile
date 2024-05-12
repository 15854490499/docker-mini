C = gcc
CXX = g++
ROOT := $(shell pwd)
SUBDIR := utils \
		  lxcapi \
		  capi \
		  configs \
		  http \
		  libocispec \
		  log \
		  client/grpc/cmake/build \
		  client/grpc \
		  main \
		  main/daemon \
		  net \
		  registry \
		  storage 

OBJ_DIR := $(ROOT)/obj
BIN_DIR := $(ROOT)/bin
CLIENT_BIN := docker-mini
DAEMON_BIN := docker-minid
CLIENT_OBJ := client_asynclog.o \
			  log.o \
			  utils.o \
			  lxcapi.o \
			  client_image_api.o \
			  client_container_api.o \
			  container.grpc.pb.cc.o \
			  container.pb.cc.o \
			  image.grpc.pb.cc.o \
			  image.pb.cc.o \
			  container_client.o \
			  image_client.o \
			  grpc_connect.o \
			  cni_anno_port_mappings.o \
			  cni_inner_port_mapping.o \
			  network_port_binding.o \
			  json_common.o \
		      defs.o \
		      read-file.o \
			  oci_runtime_config_linux.o \
			  oci_runtime_defs.o \
			  oci_runtime_defs_linux.o \
			  oci_runtime_spec.o \
			  parse_cmd.o \
			  main.o

DAEMON_OBJ := network.o \
			  nl.o \
			  http.o \
			  utils.o \
			  sha256.o \
			  timestamp.o \
		 	  json_common.o \
		      defs.o \
		      read-file.o \
			  container_config.o \
			  container_inspect.o \
			  container_network_settings.o \
			  docker_image_history.o \
			  docker_image_rootfs.o \
			  docker_image_config_v2.o \
			  docker_types_mount_point.o \
			  registry_auths.o \
			  registry_manifest_list.o \
			  registry_manifest_schema2.o \
			  registry_manifest_schema1.o \
			  registry_token.o \
			  storage_spec.o \
			  storage_storage.o \
			  storage_entry.o \
			  storage_layer.o \
			  storage_rootfs.o \
			  storage_mount_point.o \
			  cni_anno_port_mappings.o \
			  cni_inner_port_mapping.o \
			  network_port_binding.o \
			  oci_image_defs_descriptor.o \
			  oci_image_index.o \
			  oci_image_manifest.o \
			  oci_image_content_descriptor.o \
			  oci_image_spec.o \
			  oci_runtime_config_linux.o \
			  oci_runtime_defs.o \
			  oci_runtime_defs_linux.o \
			  oci_runtime_spec.o \
			  asynclog.o \
			  log.o \
			  configs_constants.o \
			  archive.o \
			  fs.o \
			  registry.o \
			  storage.o \
			  layer.o \
			  driver.o \
			  project_quota.o \
			  rootfs.o \
			  lxcapi.o \
			  image_api.o \
			  container_api.o \
			  config.o \
			  container.grpc.pb.cc.o \
			  container.pb.cc.o \
			  image.grpc.pb.cc.o \
			  image.pb.cc.o \
			  grpc_service.o \
			  service_common.o \
			  grpc_image_service.o \
			  grpc_container_service.o \
			  daemon_main.o


export C CXX C_LINK OBJ_DIR BIN_DIR CLIENT_BIN DAEMON_BIN CLIENT_OBJ DAEMON_OBJ ROOT LXC_PATH GRPC_PATH

all: CHECKDIR $(SUBDIR) LINKER

CHECKDIR:
	mkdir -p $(OBJ_DIR) $(BIN_DIR)

LINKER : $(SUBDIR)
	make -C obj

$(SUBDIR) : ECHO
	make -C $@

ECHO:
		@echo $(SUBDIR)
		@echo begin compile
clean:
	rm -rf $(OBJ_DIR)/*.o $(BIN_DIR)
