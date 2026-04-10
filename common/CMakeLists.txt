add_library(swg_common STATIC
  src/config.cpp
  src/hos_caps.cpp
  src/log.cpp
  src/state_machine.cpp
)

target_include_directories(swg_common
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(CMAKE_SYSTEM_NAME STREQUAL "NintendoSwitch")
  target_compile_definitions(swg_common PUBLIC SWG_PLATFORM_SWITCH=1)
endif()

swg_apply_defaults(swg_common)
