# pos is header‑only: use an INTERFACE library
add_library(pos INTERFACE)

# Expose all headers under include/pos/ as <pos/...>
target_include_directories(pos INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>    # for `make install`
)

# If pos depends on FSE at compile/link time:
target_link_libraries(pos INTERFACE
 fse
)
