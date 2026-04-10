cmake_minimum_required(VERSION 3.21)

project(WGSysModule VERSION 0.1.0 LANGUAGES CXX)

option(SWG_BUILD_HOST_TOOLS "Build host-side development stubs and CLIs" ON)
option(SWG_BUILD_SWITCH_TARGETS "Enable Switch-targeted configuration slices" OFF)
option(SWG_BUILD_TESTS "Build host-side tests" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(SWG_BUILD_TESTS)
  include(CTest)
endif()

function(swg_apply_defaults target_name)
  target_compile_features(${target_name} PUBLIC cxx_std_17)

  if(MSVC)
    target_compile_options(${target_name} PRIVATE /W4 /permissive-)
  else()
    target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endfunction()

add_subdirectory(common)
add_subdirectory(sdk)
add_subdirectory(sysmodule)
add_subdirectory(overlay)
add_subdirectory(manager)

if(SWG_BUILD_TESTS AND BUILD_TESTING)
  add_subdirectory(tests)
endif()

message(STATUS "SWG host tools: ${SWG_BUILD_HOST_TOOLS}")
message(STATUS "SWG Switch-target configuration: ${SWG_BUILD_SWITCH_TARGETS}")
