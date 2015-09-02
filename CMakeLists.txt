cmake_minimum_required(VERSION 3.2)
project(tc)

set(CMAKE_PREFIX_PATH "/opt/local")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(FindGMP)
include(FindMHASH)
include(FindCheck)

find_package(GMP REQUIRED)
message("gmp include ${GMP_INCLUDE_DIR}")
include_directories(${GMP_INCLUDE_DIRS})

find_package(MHASH REQUIRED)
include_directories(${MHASH_INCLUDE_DIR})

find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})

find_package(Threads REQUIRED)

set(SOURCE_FILES
    algorithms_base64.c
    algorithms_generate_keys.c
    algorithms_join_signatures.c
    algorithms_node_sign.c
    algorithms_pkcs1_encoding.c
    algorithms_rsa_verify.c
    algorithms_verify_signature.c
    structs_init.c
    structs_serialization.c
    mathutils.h
    poly.c
    random.c
    tc.h
    tc_internal.h
    unit_test.h)

add_library(tc STATIC ${SOURCE_FILES} )
message(tc ${GMP_LIBRARIES} ${MHASH_LIBRARIES} ${CHECK_LIBRARIES})
target_link_libraries(tc ${CMAKE_THREAD_LIBS_INIT} ${GMP_LIBRARIES} ${MHASH_LIBRARIES} ${CHECK_LIBRARIES})


add_executable(check_algorithms check_algorithms.c)
target_link_libraries(check_algorithms tc ${CMAKE_THREAD_LIBS_INIT})

add_executable(main main.c)
target_link_libraries(main tc ${CMAKE_THREAD_LIBS_INIT})
