add_library(swg_sdk STATIC
  src/app_session.cpp
  src/client.cpp
  src/compat_bridge.cpp
  src/compat_bridge_switch.cpp
  src/session_socket.cpp
  src/switch_transport.cpp
  src/tunnel_datagram.cpp
  src/tunnel_stream.cpp
)

if(SWG_ENABLE_ENET_ADAPTER)
  if(NOT SWG_ENET_ADAPTER_INCLUDE_DIR)
    message(FATAL_ERROR "SWG_ENABLE_ENET_ADAPTER requires SWG_ENET_ADAPTER_INCLUDE_DIR")
  endif()

  target_sources(swg_sdk PRIVATE src/enet_compat.cpp)
  target_include_directories(swg_sdk PRIVATE ${SWG_ENET_ADAPTER_INCLUDE_DIR})
endif()

target_include_directories(swg_sdk
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(swg_sdk
  PUBLIC
    swg_common
)

if(CMAKE_SYSTEM_NAME STREQUAL "NintendoSwitch")
  if(TARGET MbedTLS::mbedtls)
    target_link_libraries(swg_sdk PRIVATE MbedTLS::mbedtls)
  elseif(TARGET mbed::tls)
    target_link_libraries(swg_sdk PRIVATE mbed::tls)
  else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(MBEDTLS REQUIRED IMPORTED_TARGET mbedtls)
    pkg_check_modules(MBEDX509 REQUIRED IMPORTED_TARGET mbedx509)
    target_link_libraries(swg_sdk PRIVATE PkgConfig::MBEDTLS PkgConfig::MBEDX509)
  endif()
endif()

swg_apply_defaults(swg_sdk)
