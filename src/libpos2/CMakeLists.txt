add_library(lib_pos2 STATIC libpos2.cpp)

set_target_properties(lib_pos2 PROPERTIES
    OUTPUT_NAME pos2
    DISABLE_RETAIN_X_VALUES ON
)

target_link_libraries(lib_pos2 PUBLIC pos2_base)

install(TARGETS lib_pos2
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
