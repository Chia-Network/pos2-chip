add_executable(solver
  solver_main.cpp
)

if (CP_RETAIN_X_VALUES)
  target_compile_definitions(solver PRIVATE
    -DRETAIN_X_VALUES=1
    -DRETAIN_X_VALUES_TO_T3=1
  )
endif()

# Enable hardware AES on 64-bit ARM (e.g., Raspberry Pi 5)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|armv8")
    target_compile_options(solver PRIVATE
        -march=armv8-a+crypto
    )
endif()


target_include_directories(solver PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

# Ensure solver can include and link FSE (PlotFile.hpp includes fse.h)
target_link_libraries(solver PRIVATE fse)
