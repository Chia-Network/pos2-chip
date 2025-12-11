add_executable(prover
    prover_main.cpp
)

# Enable hardware AES on 64-bit ARM (e.g., Raspberry Pi 5)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|armv8")
    target_compile_options(prover PRIVATE
        -march=armv8-a+crypto
    )
# Enable AES-NI on x86_64 (Intel/AMD, e.g., Ubuntu desktop)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        # Explicitly enable AES-NI and friends
        target_compile_options(prover PRIVATE
            -maes
        )
    endif()
endif()

target_include_directories(prover PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

# Prover needs FSE headers (via PlotFile.hpp). Link the fse target so includes and link are available.
target_link_libraries(prover PRIVATE fse)
