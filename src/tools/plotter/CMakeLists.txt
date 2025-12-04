add_executable(plotter
  plotter_main.cpp
)

if (CP_RETAIN_X_VALUES)
  target_compile_definitions(plotter PRIVATE
    -DRETAIN_X_VALUES=1
    -DRETAIN_X_VALUES_TO_T3=1
  )
endif()

# Enable hardware AES on 64-bit ARM (e.g., Raspberry Pi 5)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|armv8")
    target_compile_options(solver PRIVATE
        -march=armv8-a+crypto
    )
# Enable AES-NI on x86_64 (Intel/AMD, e.g., Ubuntu desktop)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        # Explicitly enable AES-NI and friends
        target_compile_options(analytics PRIVATE
            -maes
        )
    endif()
endif()

target_include_directories(plotter PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

target_link_libraries(plotter PRIVATE
  fse
)
