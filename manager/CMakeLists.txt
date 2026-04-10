if(SWG_BUILD_HOST_TOOLS)
  add_executable(swg_manager_stub
    src/main.cpp
  )

  target_link_libraries(swg_manager_stub
    PRIVATE
      swg_sdk
      swg_sysmodule_core
  )

  swg_apply_defaults(swg_manager_stub)
endif()

if(SWG_BUILD_SWITCH_TARGETS AND CMAKE_SYSTEM_NAME STREQUAL "NintendoSwitch")
  add_executable(swg_manager_switch
    src/switch_main.cpp
  )

  target_link_libraries(swg_manager_switch
    PRIVATE
      swg_sdk
  )

  swg_apply_defaults(swg_manager_switch)

  nx_create_nro(swg_manager_switch_package
    TARGET swg_manager_switch
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/swg_manager.nro
  )

  set(SWG_MANAGER_STAGE_DIR ${CMAKE_CURRENT_BINARY_DIR}/switch)
  set(SWG_MANAGER_STAGE_NRO ${SWG_MANAGER_STAGE_DIR}/swg_manager.nro)

  add_custom_command(
    OUTPUT ${SWG_MANAGER_STAGE_NRO}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWG_MANAGER_STAGE_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_CURRENT_BINARY_DIR}/swg_manager.nro
      ${SWG_MANAGER_STAGE_NRO}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/swg_manager.nro
    COMMENT "Staging Switch manager NRO"
    VERBATIM
  )

  add_custom_target(swg_manager_switch_stage ALL
    DEPENDS ${SWG_MANAGER_STAGE_NRO}
  )
endif()
