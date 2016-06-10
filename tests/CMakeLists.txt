cmake_minimum_required(VERSION 2.8)

include_directories(${tclib_SOURCE_DIR}/include)
link_directories(${PROJECT_BINARY_DIR})
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -g")

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(REALTIME_LIBRARIES "rt")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${tclib_SOURCE_DIR}/cmake)
include(FindGMP)
include(FindMHASH)
include(FindCheck)

find_package(GMP REQUIRED)
message("gmp include ${GMP_INCLUDE_DIR}")
include_directories(${GMP_INCLUDE_DIRS})

find_package(MHASH REQUIRED)
include_directories(${MHASH_INCLUDE_DIR})

find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIR})
link_directories(${CHECK_LIBRARIES})

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)

set(SOURCE_FILES
    test_algorithms_generate_keys.c
    test_algorithms_join_signatures.c
    test.c
    test_check_algorithms.c
    test_structs_serialization.c test_base64.c test_poly.c)

add_executable(tests ${SOURCE_FILES} )
target_link_libraries(tests tc ${GMP_LIBRARIES} ${MHASH_LIBRARIES} ${CHECK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} m ${REALTIME_LIBRARIES})
add_test(NAME tests COMMAND tests)
add_dependencies(check tests)
