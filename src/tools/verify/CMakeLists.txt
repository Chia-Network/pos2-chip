add_executable(verify
    verify_main.cpp
)
  
target_include_directories(verify PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)