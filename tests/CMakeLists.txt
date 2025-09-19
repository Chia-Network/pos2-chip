message("Tests Enabled")

macro(new_test name source_file)
add_executable(${name} ${source_file})
target_include_directories(${name} PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
  ../lib/doctest
)

add_test(NAME ${name}_test COMMAND ${name} )

endmacro()

new_test(plot_file test_plot_file.cpp)
