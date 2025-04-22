# lib/common/CMakeLists.txt

# common is header-only
add_library(common INTERFACE)

# Expose include/common/ as the root for <common/...> headers
target_include_directories(common INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
