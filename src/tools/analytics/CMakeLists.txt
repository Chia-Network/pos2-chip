add_executable(analytics
    analytics_main.cpp
)

# Enable hardware AES on 64-bit ARM (e.g., Raspberry Pi 5)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|armv8")
    target_compile_options(analytics PRIVATE
        -march=armv8-a+crypto
        -mtune=cortex-a76
    )
endif()
  
target_include_directories(analytics PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

# Analytics uses PlotFile.hpp which includes fse.h; ensure it can find headers / link the fse lib
target_link_libraries(analytics PRIVATE fse)
