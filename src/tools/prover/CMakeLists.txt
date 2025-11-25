add_executable(prover
    prover_main.cpp
)
  
target_include_directories(prover PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)
  
# Prover needs FSE headers (via PlotFile.hpp). Link the fse target so includes and link are available.
target_link_libraries(prover PRIVATE fse)