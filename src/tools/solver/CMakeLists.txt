add_executable(solver
  solver_main.cpp
)

if (CP_RETAIN_X_VALUES)
  target_compile_definitions(solver PRIVATE
    -DRETAIN_X_VALUES=1
    -DRETAIN_X_VALUES_TO_T3=1
  )
endif()


target_include_directories(solver PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

# required for Pi / 32-bit ARM
# TODO: detect 32 bit ARM
#target_link_libraries(solver PRIVATE
#  atomic
#)

# Ensure solver can include and link FSE (PlotFile.hpp includes fse.h)
target_link_libraries(solver PRIVATE fse)
