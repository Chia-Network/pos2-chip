add_executable(solver
  solver_main.cpp
)

# Locate TBB
find_package(TBB REQUIRED)

target_include_directories(solver PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

# Link against TBB
target_link_libraries(solver PRIVATE
  TBB::tbb
)