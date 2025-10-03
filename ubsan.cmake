set(CMAKE_C_FLAGS_INIT "-fsanitize=undefined -fno-sanitize-recover=all")
set(CMAKE_CXX_FLAGS_INIT "-fsanitize=undefined -fno-sanitize-recover=all")

# only clang supports type sanitizer
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
set(CMAKE_C_FLAGS_INIT "-fsanitize=memory -fsanitize=type ${CMAKE_C_FLAGS_INIT}")
set(CMAKE_CXX_FLAGS_INIT "-fsanitize=memory -fsanitize=type ${CMAKE_CXX_FLAGS_INIT}")
endif()
