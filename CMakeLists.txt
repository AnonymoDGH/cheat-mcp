cmake_minimum_required(VERSION 3.16)
project(cheatmcp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/utf-8 /W3 /EHsc /MP)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

file(GLOB CHEATMCP_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.cpp)
add_executable(cheatmcp ${CHEATMCP_SOURCES})
target_include_directories(cheatmcp PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(cheatmcp PRIVATE
  psapi
  iphlpapi
  ws2_32
  advapi32
  user32
  shell32
  ntdll
)

# Multi-monitor / DPI friendly console
if(MSVC)
  target_compile_options(cheatmcp PRIVATE /permissive-)
endif()
