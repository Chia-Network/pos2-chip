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
new_test(plot_challenge_solve_validate test_plot_challenge_solve_validate.cpp)
new_test(solve test_solver.cpp)
new_test(proof_fragment_scan_filter test_ProofFragmentScanFilter.cpp)
new_test(chaining test_chaining.cpp)
new_test(utils test_Utils.cpp)
new_test(parallel test_parallel_for_range.cpp)
new_test(blake_hash test_blake.cpp)
new_test(proof_core_math test_proof_core_math.cpp)
