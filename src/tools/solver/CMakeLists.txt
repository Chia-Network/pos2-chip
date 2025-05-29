add_executable(solver
  solver_main.cpp
)

if (CP_RETAIN_X_VALUES)
  target_compile_definitions(solver PRIVATE
    -DRETAIN_X_VALUES=1
    -DRETAIN_X_VALUES_TO_T3=1
  )
endif()


# Locate TBB
find_package(TBB REQUIRED)

target_include_directories(solver PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

# Link against TBB
target_link_libraries(solver PRIVATE
  TBB::tbb
  atomic # required for Pi / 32-bit ARM
)