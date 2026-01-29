add_library(lib_plotter STATIC libpos2.cpp)

set_target_properties(lib_plotter PROPERTIES
    OUTPUT_NAME plotter2
    DISABLE_RETAIN_X_VALUES ON
)

target_link_libraries(lib_plotter PUBLIC pos2_base)
