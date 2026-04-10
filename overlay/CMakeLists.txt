if(SWG_BUILD_HOST_TOOLS)
  add_executable(swg_overlay_stub
    src/main.cpp
  )

  target_link_libraries(swg_overlay_stub
    PRIVATE
      swg_sdk
      swg_sysmodule_core
  )

  swg_apply_defaults(swg_overlay_stub)
endif()
