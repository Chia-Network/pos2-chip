set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Interface library shared by pos2 targets
add_library(pos2_base INTERFACE)
target_include_directories(pos2_base INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(pos2_base INTERFACE
  fse
)

if (CP_RETAIN_X_VALUES)
  target_compile_definitions(pos2_base INTERFACE
    $<$<NOT:$<BOOL:$<TARGET_PROPERTY:DISABLE_RETAIN_X_VALUES>>>:
        RETAIN_X_VALUES=1
        RETAIN_X_VALUES_TO_T3=1
    >
  )
endif()


# Enable hardware AES on 64-bit ARM (e.g., Raspberry Pi 5)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|armv8")
    target_compile_options(pos2_base INTERFACE
        -march=armv8-a+crypto
    )
# Enable AES-NI on x86_64 (Intel/AMD)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        # Explicitly enable AES-NI and friends
        target_compile_options(pos2_base INTERFACE
            -maes
        )
    endif()
endif()

message("CP_RETAIN_X_VALUES:     ${CP_RETAIN_X_VALUES}")
message("CP_BUILD_TESTS:         ${CP_BUILD_TESTS}")
message("CP_ENABLE_LIBPOS2_ONLY: ${CP_ENABLE_LIBPOS2_ONLY}")
message("CP_ENABLE_LIBPOS2:      ${CP_ENABLE_LIBPOS2}")
message("CP_ENABLE_PLOTTER:      ${CP_ENABLE_PLOTTER}")
message("CP_ENABLE_SOLVER:       ${CP_ENABLE_SOLVER}")
message("CP_ENABLE_PROVER:       ${CP_ENABLE_PROVER}")
message("CP_ENABLE_ANALYTICS:    ${CP_ENABLE_ANALYTICS}")

if (CP_ENABLE_PLOTTER)
    add_subdirectory(tools/plotter)
endif()

if (CP_ENABLE_SOLVER)
    add_subdirectory(tools/solver)
endif()

if (CP_ENABLE_PROVER)
    add_subdirectory(tools/prover)
endif()

if (CP_ENABLE_ANALYTICS)
    add_subdirectory(tools/analytics)
endif()

if (CP_ENABLE_LIBPOS2)
    add_subdirectory(libpos2)
endif()
