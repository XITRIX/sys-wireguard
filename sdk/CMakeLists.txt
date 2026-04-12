add_library(swg_sdk STATIC
  src/app_session.cpp
  src/client.cpp
  src/session_socket.cpp
  src/switch_transport.cpp
  src/tunnel_datagram.cpp
  src/tunnel_stream.cpp
)

target_include_directories(swg_sdk
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(swg_sdk
  PUBLIC
    swg_common
)

swg_apply_defaults(swg_sdk)
