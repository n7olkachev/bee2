if(MSVC)
  # disable the security warnings for fopen()
  add_definitions(/D _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(bels
	bels.c
)

target_link_libraries(bels bee2_static)

install(TARGETS bels
        DESTINATION ${BIN_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
