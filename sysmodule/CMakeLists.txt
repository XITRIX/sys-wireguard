add_library(swg_sysmodule_core STATIC
  src/host_transport.cpp
  src/local_service.cpp
  src/wg_engine.cpp
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

if(SWG_BUILD_SWITCH_TARGETS AND CMAKE_SYSTEM_NAME STREQUAL "NintendoSwitch")
  file(READ ${CMAKE_CURRENT_SOURCE_DIR}/sysmodule.json SWG_SYSMODULE_JSON)
  string(JSON SWG_SYSMODULE_TITLE_ID GET "${SWG_SYSMODULE_JSON}" title_id)
  string(JSON SWG_SYSMODULE_NAME GET "${SWG_SYSMODULE_JSON}" name)
  string(REGEX REPLACE "^0x" "" SWG_SYSMODULE_TITLE_ID_HEX "${SWG_SYSMODULE_TITLE_ID}")
  set(SWG_SYSMODULE_TOOLBOX_JSON ${CMAKE_CURRENT_BINARY_DIR}/toolbox.json)

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/toolbox.json.in
    ${SWG_SYSMODULE_TOOLBOX_JSON}
    @ONLY
  )

  add_executable(swg_control_sysmodule
    src/switch_main.cpp
  )

  target_link_libraries(swg_control_sysmodule
    PRIVATE
      swg_sysmodule_core
  )

  swg_apply_defaults(swg_control_sysmodule)

  nx_create_exefs(swg_control_sysmodule_package
    TARGET swg_control_sysmodule
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/swg_sysmodule.nsp
    CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/sysmodule.json
  )

  set(SWG_SYSMODULE_STAGE_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/atmosphere/contents/${SWG_SYSMODULE_TITLE_ID_HEX}
  )
  set(SWG_SYSMODULE_STAGE_EXEFS
    ${SWG_SYSMODULE_STAGE_DIR}/exefs.nsp
  )
  set(SWG_SYSMODULE_STAGE_BOOT_FLAG
    ${SWG_SYSMODULE_STAGE_DIR}/flags/boot2.flag
  )
  set(SWG_SYSMODULE_STAGE_TOOLBOX
    ${SWG_SYSMODULE_STAGE_DIR}/toolbox.json
  )

  add_custom_command(
    OUTPUT
      ${SWG_SYSMODULE_STAGE_EXEFS}
      ${SWG_SYSMODULE_STAGE_BOOT_FLAG}
      ${SWG_SYSMODULE_STAGE_TOOLBOX}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWG_SYSMODULE_STAGE_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWG_SYSMODULE_STAGE_DIR}/flags
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_CURRENT_BINARY_DIR}/swg_sysmodule.nsp
      ${SWG_SYSMODULE_STAGE_EXEFS}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${SWG_SYSMODULE_TOOLBOX_JSON}
      ${SWG_SYSMODULE_STAGE_TOOLBOX}
    COMMAND ${CMAKE_COMMAND} -E touch ${SWG_SYSMODULE_STAGE_BOOT_FLAG}
    DEPENDS
      ${CMAKE_CURRENT_BINARY_DIR}/swg_sysmodule.nsp
      ${SWG_SYSMODULE_TOOLBOX_JSON}
    COMMENT "Staging Atmosphere sysmodule layout for ${SWG_SYSMODULE_TITLE_ID_HEX}"
    VERBATIM
  )

  add_custom_target(swg_control_sysmodule_stage ALL
    DEPENDS
      ${SWG_SYSMODULE_STAGE_EXEFS}
      ${SWG_SYSMODULE_STAGE_BOOT_FLAG}
      ${SWG_SYSMODULE_STAGE_TOOLBOX}
  )
endif()
