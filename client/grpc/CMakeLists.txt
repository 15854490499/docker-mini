cmake_minimum_required(VERSION 3.8)

project(GRPC C CXX)

include(./common.cmake)

# Proto file
get_filename_component(cont_proto "./protos/container.proto" ABSOLUTE)
get_filename_component(cont_proto_path "${cont_proto}" PATH)
get_filename_component(img_proto "./protos/image.proto" ABSOLUTE)
get_filename_component(img_proto_path "${img_proto}" PATH)

# Generated sources
set(cont_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/../../container.pb.cc")
set(cont_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../../container.pb.h")
set(cont_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/container.grpc.pb.cc")
set(cont_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/container.grpc.pb.h")
add_custom_command(
      OUTPUT "${cont_proto_srcs}" "${cont_proto_hdrs}" "${cont_grpc_srcs}" "${cont_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}/../.."
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}/../.."
        -I "${cont_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${cont_proto}"
      DEPENDS "${cont_proto}")

set(img_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/../../image.pb.cc")
set(img_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../../image.pb.h")
set(img_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/image.grpc.pb.cc")
set(img_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/image.grpc.pb.h")
add_custom_command(
      OUTPUT "${img_proto_srcs}" "${img_proto_hdrs}" "${img_grpc_srcs}" "${img_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}/../.."
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}/../.."
        -I "${img_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${img_proto}"
      DEPENDS "${img_proto}")

include_directories("${CMAKE_CURRENT_BINARY_DIR}")

add_library(cont_grpc_proto
  ${cont_grpc_srcs}
  ${cont_grpc_hdrs}
  ${cont_proto_srcs}
  ${cont_proto_hdrs})

add_library(img_grpc_proto
  ${img_grpc_srcs}
  ${img_grpc_hdrs}
  ${img_proto_srcs}
  ${img_proto_hdrs})

target_link_libraries(cont_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

target_link_libraries(img_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

