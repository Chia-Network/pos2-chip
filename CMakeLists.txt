cmake_minimum_required(VERSION 3.15)
project(pos2-chip LANGUAGES C CXX)

enable_testing()

include(Options.cmake)

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

add_subdirectory(src/tools/plotter)
add_subdirectory(src/tools/solver)
add_subdirectory(src/tools/prover)
add_subdirectory(src/tools/analytics)

add_subdirectory(tests)
