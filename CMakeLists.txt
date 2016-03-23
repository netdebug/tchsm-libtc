cmake_minimum_required(VERSION 2.8)

set(CMAKE_CTEST_COMMAND ctest -V)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
enable_testing()

project(tclib)
add_subdirectory(src)
add_subdirectory(tests EXCLUDE_FROM_ALL)
#subdirs(src tests)
