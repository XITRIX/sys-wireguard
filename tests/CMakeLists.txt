if(NOT SWG_BUILD_HOST_TOOLS)
  return()
endif()

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
