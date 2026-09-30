message("Tests Enabled")

macro(new_test name source_file)

add_executable(${name} ${source_file})
target_include_directories(${name} PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
  ../lib/doctest
)

# Link tests through pos2_base for headers, fse, and optional retain X definitions.
target_link_libraries(${name} PRIVATE pos2_base)

add_test(NAME ${name}_test COMMAND ${name} )
set_tests_properties(${name}_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

endmacro()

new_test(plot_file test_plot_file.cpp)
new_test(plot_group_file test_plot_group.cpp)
new_test(plot_challenge_solve_validate test_plot_challenge_solve_validate.cpp)
new_test(solve test_solver.cpp)
new_test(utils test_Utils.cpp)
new_test(bits test_bits.cpp)
new_test(gsz test_gsz.cpp)
new_test(sha256 test_sha256.cpp)
target_compile_definitions(sha256 PRIVATE SHA256_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/test_data/sha256")
new_test(parallel test_parallel_for_range.cpp)
new_test(blake_hash test_blake.cpp)
new_test(chunk_compressor test_chunk_compressor.cpp)
new_test(chainer test_chainer.cpp)
new_test(chain_average test_chain_average.cpp)
new_test(aes test_aes.cpp)
new_test(compute_last_link_extra_threshold test_compute_last_link_extra_threshold.cpp)
