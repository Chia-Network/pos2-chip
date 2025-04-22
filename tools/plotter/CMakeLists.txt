# 1) Define your executable and its .cpp
add_executable(plotter
    src/main.cpp
    # … add more .cpp implementation files here if you split them out
)

# 2) Point at your tool‑local headers
target_include_directories(plotter PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 3) Link against your core 'pos' INTERFACE library
#    (this also pulls in fse includes/links transitively)
target_link_libraries(plotter PRIVATE
    pos
    common
)

# (Optionally enforce C++20 per‑target—if you didn’t set it globally)
# target_compile_features(plotter PRIVATE cxx_std_20)

