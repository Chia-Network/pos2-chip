message("Tests Enabled")

macro(new_test name source_file)
add_executable(${name} ${source_file})
target_include_directories(${name} PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
  ../lib/doctest
)

target_compile_options(${name} PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:
    -include test_util.h
  >
  $<$<CXX_COMPILER_ID:MSVC>:
    /FItest_util.h
  >
)

add_test(NAME ${name}_test COMMAND ${name} )

endmacro()

new_test(plot_file test_all.cpp)
