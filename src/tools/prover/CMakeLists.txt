add_executable(prover
    prover_main.cpp
)
  
target_include_directories(prover PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)
  
#target_link_libraries(prover PRIVATE
#    fse
#)