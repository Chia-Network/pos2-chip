add_executable(analytics
    analytics_main.cpp
)
  
target_include_directories(analytics PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

# Analytics uses PlotFile.hpp which includes fse.h; ensure it can find headers / link the fse lib
target_link_libraries(analytics PRIVATE fse)
