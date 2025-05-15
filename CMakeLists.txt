cmake_minimum_required(VERSION 3.15)
project(pos2-chip LANGUAGES C CXX)

include(Options.cmake)

# ─── Enforce C++20 ─────────────────────
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ─── Subprojects ───────────────────────
add_subdirectory(lib/fse)
add_subdirectory(src/tools/plotter)
add_subdirectory(src/tools/solver)
add_subdirectory(src/tools/prover)

# tests, other tools…
if (CP_ENABLE_TESTS)
    add_subdirectory(tests)
endif()
