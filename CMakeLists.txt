cmake_minimum_required(VERSION 3.15)
project(pos2-chip LANGUAGES C CXX)

# ─── Enforce C++20 ─────────────────────
set(CMAKE_CXX_STANDARD      20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS    OFF)

# ─── Subprojects ───────────────────────
add_subdirectory(lib/fse)
add_subdirectory(lib/pos)
add_subdirectory(lib/common)
add_subdirectory(tools/plotter)

# tests, other tools…
# add_subdirectory(tests)
