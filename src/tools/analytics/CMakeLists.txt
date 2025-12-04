add_executable(analytics
    analytics_main.cpp
)

# Enable hardware AES on 64-bit ARM (e.g., Raspberry Pi 5)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|armv8")
    target_compile_options(analytics PRIVATE
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
  
target_include_directories(analytics PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

# Analytics uses PlotFile.hpp which includes fse.h; ensure it can find headers / link the fse lib
target_link_libraries(analytics PRIVATE fse)
