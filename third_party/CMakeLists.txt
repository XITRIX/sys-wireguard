set(SWG_WIREGUARD_LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/wireguard-lwip)

add_library(wireguard_lwip_core STATIC
  ${SWG_WIREGUARD_LWIP_DIR}/src/crypto.c
  ${SWG_WIREGUARD_LWIP_DIR}/src/wireguard.c
  ${SWG_WIREGUARD_LWIP_DIR}/src/crypto/refc/blake2s.c
  ${SWG_WIREGUARD_LWIP_DIR}/src/crypto/refc/chacha20.c
  ${SWG_WIREGUARD_LWIP_DIR}/src/crypto/refc/chacha20poly1305.c
  ${SWG_WIREGUARD_LWIP_DIR}/src/crypto/refc/poly1305-donna.c
  ${SWG_WIREGUARD_LWIP_DIR}/src/crypto/refc/x25519.c
  wireguard_lwip_platform.cpp
)

target_include_directories(wireguard_lwip_core
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/wireguard_lwip_compat/include
    ${SWG_WIREGUARD_LWIP_DIR}/src
)

if(CMAKE_SYSTEM_NAME STREQUAL "NintendoSwitch")
  target_compile_definitions(wireguard_lwip_core PUBLIC SWG_PLATFORM_SWITCH=1)
endif()

if(TARGET MbedTLS::mbedcrypto)
  target_link_libraries(wireguard_lwip_core
    PUBLIC
      MbedTLS::mbedcrypto
  )
elseif(TARGET mbed::crypto)
  target_link_libraries(wireguard_lwip_core
    PUBLIC
      mbed::crypto
  )
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(MBEDCRYPTO REQUIRED IMPORTED_TARGET mbedcrypto)

  target_link_libraries(wireguard_lwip_core
    PUBLIC
      PkgConfig::MBEDCRYPTO
  )
endif()

target_compile_features(wireguard_lwip_core PUBLIC c_std_99 cxx_std_17)

if(NOT MSVC)
  target_compile_options(wireguard_lwip_core PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-Wno-unused-function>
    $<$<COMPILE_LANGUAGE:C>:-Wno-unused-variable>
    $<$<COMPILE_LANG_AND_ID:C,GNU>:-Wno-stringop-overread>
  )
endif()
