add_library(swg_common STATIC
  src/config.cpp
  src/hos_caps.cpp
  src/ipv4_udp.cpp
  src/ipc_codec.cpp
  src/log.cpp
  src/state_machine.cpp
  src/tunnel_dns.cpp
  src/wg_crypto.cpp
  src/wg_handshake.cpp
  src/wg_profile.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MBEDCRYPTO REQUIRED IMPORTED_TARGET mbedcrypto)

target_include_directories(swg_common
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(CMAKE_SYSTEM_NAME STREQUAL "NintendoSwitch")
  target_compile_definitions(swg_common PUBLIC SWG_PLATFORM_SWITCH=1)
endif()

target_link_libraries(swg_common
  PUBLIC
    PkgConfig::MBEDCRYPTO
)

swg_apply_defaults(swg_common)
