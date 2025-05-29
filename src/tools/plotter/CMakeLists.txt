add_executable(plotter
  plotter_main.cpp
)

if (CP_RETAIN_X_VALUES)
  target_compile_definitions(plotter PRIVATE
    -DRETAIN_X_VALUES=1
    -DRETAIN_X_VALUES_TO_T3=1
  )
endif()

target_include_directories(plotter PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

target_link_libraries(plotter PRIVATE
  fse
)
