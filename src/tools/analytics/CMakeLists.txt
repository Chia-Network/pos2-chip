add_executable(analytics
    analytics_main.cpp
)
  
target_include_directories(analytics PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)
  