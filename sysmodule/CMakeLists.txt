add_library(swg_sysmodule_core STATIC
  src/host_transport.cpp
  src/local_service.cpp
)

target_include_directories(swg_sysmodule_core
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../sdk/include
)

target_link_libraries(swg_sysmodule_core
  PUBLIC
    swg_common
)

swg_apply_defaults(swg_sysmodule_core)

if(SWG_BUILD_HOST_TOOLS)
  add_executable(swg_sysmodule_stub
    src/main.cpp
  )

  target_link_libraries(swg_sysmodule_stub
    PRIVATE
      swg_sdk
      swg_sysmodule_core
  )

  swg_apply_defaults(swg_sysmodule_stub)
endif()
