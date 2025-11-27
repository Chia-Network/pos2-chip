message("Tests Enabled")

macro(new_test name source_file)
add_executable(${name} ${source_file})
target_include_directories(${name} PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
  ../lib/doctest
)

## Link tests against fse so tests that include PlotFile.hpp (which includes fse.h)
## get the proper include directory and link the library.
## target_link_libraries(${name} PRIVATE fse)

add_test(NAME ${name}_test COMMAND ${name} )

endmacro()

new_test(plot_file test_plot_file.cpp)
new_test(plot_challenge_solve_validate test_plot_challenge_solve_validate.cpp)
new_test(solve test_solver.cpp)
new_test(utils test_Utils.cpp)
new_test(parallel test_parallel_for_range.cpp)
new_test(blake_hash test_blake.cpp)
new_test(chunk_compressor test_chunk_compressor.cpp)
new_test(chainer test_chainer.cpp)

# Link the fse test executable with the fse library target so FSE symbols are
# resolved at link time.
target_link_libraries(plot_file PRIVATE fse)
target_link_libraries(plot_challenge_solve_validate PRIVATE fse)
target_link_libraries(chunk_compressor PRIVATE fse)
target_link_libraries(chainer PRIVATE fse)
target_link_libraries(solve PRIVATE fse)
