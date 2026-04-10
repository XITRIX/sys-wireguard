if(NOT SWG_BUILD_HOST_TOOLS)
  return()
endif()

add_executable(swg_tests
  config_tests.cpp
)

target_link_libraries(swg_tests
  PRIVATE
    swg_sdk
    swg_sysmodule_core
)

swg_apply_defaults(swg_tests)

add_test(NAME swg_tests COMMAND swg_tests)
