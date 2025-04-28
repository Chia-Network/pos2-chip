message("Tests Enabled")

add_executable(tests
  test_all.cpp
)
set_target_properties(tests PROPERTIES 
  EXCLUDE_FROM_ALL ON
  OUTPUT_NAME "test"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
target_compile_definitions(tests PRIVATE
  CP_TEST_MODE=1
)
target_include_directories(tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ../lib/doctest
)

# target_link_libraries(tests PRIVATE lib_plotter)

target_compile_options(tests PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:
    -include test_util.h
  >
  $<$<CXX_COMPILER_ID:MSVC>:
    /FItest_util.h
  >
)



# target_link_libraries(tests PRIVATE cpos2_lib)
