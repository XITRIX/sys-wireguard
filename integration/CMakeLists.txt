if(SWG_BUILD_HOST_TOOLS)
  add_executable(swg_integration_server
    src/host_server.cpp
  )

  if(TARGET Threads::Threads)
    target_link_libraries(swg_integration_server
      PRIVATE
        Threads::Threads
    )
  endif()

  if(WIN32)
    target_link_libraries(swg_integration_server
      PRIVATE
        ws2_32
    )
  endif()

  swg_apply_defaults(swg_integration_server)
endif()

if(SWG_BUILD_SWITCH_TARGETS AND CMAKE_SYSTEM_NAME STREQUAL "NintendoSwitch")
  add_executable(swg_integration_switch
    src/switch_main.cpp
  )

  target_link_libraries(swg_integration_switch
    PRIVATE
      swg_sdk
  )

  swg_apply_defaults(swg_integration_switch)

  nx_create_nro(swg_integration_switch_package
    TARGET swg_integration_switch
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/swg_integration_test.nro
  )

  set(SWG_INTEGRATION_STAGE_DIR ${CMAKE_CURRENT_BINARY_DIR}/switch)
  set(SWG_INTEGRATION_STAGE_NRO ${SWG_INTEGRATION_STAGE_DIR}/swg_integration_test.nro)

  add_custom_command(
    OUTPUT ${SWG_INTEGRATION_STAGE_NRO}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWG_INTEGRATION_STAGE_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_CURRENT_BINARY_DIR}/swg_integration_test.nro
      ${SWG_INTEGRATION_STAGE_NRO}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/swg_integration_test.nro
    COMMENT "Staging Switch integration test NRO"
    VERBATIM
  )

  add_custom_target(swg_integration_switch_stage ALL
    DEPENDS ${SWG_INTEGRATION_STAGE_NRO}
  )
endif()