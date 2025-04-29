add_executable(plotter
  plotter_main.cpp
)

target_include_directories(plotter PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

target_link_libraries(plotter PRIVATE
  fse
)
