cmake_minimum_required(VERSION 3.15)
project(pos2-chip LANGUAGES C CXX)

include(Options.cmake)
if(CP_BUILD_TESTS)
    include(CTest)
endif()

# ─── Enforce C++20 ─────────────────────
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ─── Subprojects ───────────────────────
if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -pedantic)
endif()

add_subdirectory(lib/fse)
add_subdirectory(src)

if (CP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
