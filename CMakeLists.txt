cmake_minimum_required(VERSION 3.21)

project(WGSysModule VERSION 0.1.0 LANGUAGES CXX)

option(SWG_BUILD_HOST_TOOLS "Build host-side development stubs and CLIs" ON)
option(SWG_BUILD_SWITCH_TARGETS "Enable Switch-targeted configuration slices" OFF)
option(SWG_BUILD_TESTS "Build host-side tests" ON)
option(SWG_BUILD_INTEGRATION_SERVER_ONLY
  "Build only the passive host integration server and skip core libraries"
  OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(SWG_BUILD_TESTS)
  include(CTest)
endif()

if(SWG_BUILD_HOST_TOOLS OR SWG_BUILD_TESTS)
  find_package(Threads REQUIRED)
endif()

if(SWG_BUILD_INTEGRATION_SERVER_ONLY AND NOT SWG_BUILD_HOST_TOOLS)
  message(FATAL_ERROR "SWG_BUILD_INTEGRATION_SERVER_ONLY requires SWG_BUILD_HOST_TOOLS=ON")
endif()

if(SWG_BUILD_INTEGRATION_SERVER_ONLY AND SWG_BUILD_SWITCH_TARGETS)
  message(FATAL_ERROR "SWG_BUILD_INTEGRATION_SERVER_ONLY requires SWG_BUILD_SWITCH_TARGETS=OFF")
endif()

function(swg_apply_defaults target_name)
  target_compile_features(${target_name} PUBLIC cxx_std_17)

  if(MSVC)
    target_compile_options(${target_name} PRIVATE /W4 /permissive-)
  else()
    target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endfunction()

if(SWG_BUILD_INTEGRATION_SERVER_ONLY)
  add_subdirectory(integration)
else()
  add_subdirectory(common)
  add_subdirectory(sdk)
  add_subdirectory(sysmodule)
  add_subdirectory(overlay)
  add_subdirectory(manager)
  add_subdirectory(integration)

  if(SWG_BUILD_TESTS AND BUILD_TESTING)
    add_subdirectory(tests)
  endif()
endif()

message(STATUS "SWG host tools: ${SWG_BUILD_HOST_TOOLS}")
message(STATUS "SWG Switch-target configuration: ${SWG_BUILD_SWITCH_TARGETS}")
message(STATUS "SWG integration server only: ${SWG_BUILD_INTEGRATION_SERVER_ONLY}")
