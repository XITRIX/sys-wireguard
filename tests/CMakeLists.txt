if(NOT SWG_BUILD_HOST_TOOLS)
  return()
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(MBEDTLS REQUIRED IMPORTED_TARGET mbedtls)
pkg_check_modules(MBEDX509 REQUIRED IMPORTED_TARGET mbedx509)

add_executable(swg_tests
  config_tests.cpp
  mitm_scaffold_tests.cpp
)

target_link_libraries(swg_tests
  PRIVATE
    swg_sdk
    swg_sysmodule_core
)

swg_apply_defaults(swg_tests)

add_test(NAME swg_tests COMMAND swg_tests)

add_executable(swg_live_handshake_probe
  live_handshake_probe.cpp
)

target_link_libraries(swg_live_handshake_probe
  PRIVATE
    swg_sdk
    swg_sysmodule_core
)

target_compile_definitions(swg_live_handshake_probe
  PRIVATE
    SWG_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

swg_apply_defaults(swg_live_handshake_probe)

add_executable(swg_live_integration_probe
  live_integration_probe.cpp
)

target_link_libraries(swg_live_integration_probe
  PRIVATE
    swg_sdk
    swg_sysmodule_core
)

target_compile_definitions(swg_live_integration_probe
  PRIVATE
    SWG_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

swg_apply_defaults(swg_live_integration_probe)

add_executable(swg_live_moonlight_control_probe
  live_moonlight_control_probe.cpp
)

target_link_libraries(swg_live_moonlight_control_probe
  PRIVATE
    swg_sdk
    swg_sysmodule_core
    PkgConfig::MBEDTLS
    PkgConfig::MBEDX509
)

target_compile_definitions(swg_live_moonlight_control_probe
  PRIVATE
    SWG_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

swg_apply_defaults(swg_live_moonlight_control_probe)
