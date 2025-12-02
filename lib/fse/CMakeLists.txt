add_library(fse STATIC
  fse/entropy_common.c
  fse/fse_compress.c
  fse/fse_decompress.c
  fse/fseU16.c
  fse/huf_compress.c
  fse/huf_decompress.c
  fse/hist.c
)

target_include_directories(fse PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/fse
)

target_compile_definitions(fse PUBLIC
  # FSE_STATIC_LINKING_ONLY=1
  FSE_MAX_MEMORY_USAGE=16
)

set(is_gcc_or_clang $<OR:$<C_COMPILER_ID:GNU>,$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>>)
set(is_msvc $<C_COMPILER_ID:MSVC>)

# These follow what's on the Makefile/vcxproj of the official build
target_compile_options(fse PRIVATE
  $<${is_gcc_or_clang}:
    $<$<CONFIG:Release>:
      -O3
    >
    $<$<CONFIG:Debug>:
      -O0
    >

    -g
    -Wall
    -Wextra
    -Wcast-qual
    -Wcast-align
    -Wshadow
    -Wstrict-aliasing=1
    -Wswitch-enum
    -Wstrict-prototypes
    -Wundef

    -Wno-bitwise-instead-of-logical
  >
  $<${is_msvc}:
    $<$<CONFIG:Release>:
      /W4
      /wd
      /O2
      /Oi
      /Oy
      /GL
      /D
      /MT
      /Zi
    >
    $<$<CONFIG:Debug>:
      /W4
      /Od
      /we
      /RTC1
      /MDd
      /Zi
    >
  >
)
