cmake_minimum_required(VERSION 3.2)
project(tclib)

set(CMAKE_PREFIX_PATH "/opt/local")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(FindGMP)
include(FindMHASH)
include(FindCheck)

find_package(GMP)
message("gmp include ${GMP_INCLUDE_DIR}")
include_directories(${GMP_INCLUDE_DIRS})

find_package(MHASH)
include_directories(${MHASH_INCLUDE_DIR})

find_package(Check)
include_directories(${CHECK_INCLUDE_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})

# if (GMP_FOUND)
#     include_directories(${GMP_INCLUDE_DIRS})
# else()
#     message(FATAL_ERROR "Cannot find GMP")
# endif()
#
# if (MHASH_FOUND)
#     include_directories(${MHASH_INCLUDE_DIRS})
# else()
#     message(FATAL_ERROR "Cannot find GMP")
# endif()
#
# if (Check_FOUND)
#     include_directories(${Check_INCLUDE_DIRS})
# else()
#    message(FATAL_ERROR "Cannot find GMP")
#endif()

set(SOURCE_FILES
    algorithms_base64.c
    algorithms_generate_keys.c
    algorithms_join_signatures.c
    algorithms_node_sign.c
    algorithms_pkcs1_encoding.c
    algorithms_rsa_verify.c
    algorithms_verify_signature.c
    init.c
    mathutils.h
    poly.c
    random.c
    tc.h
    tc_internal.h
    unit_test.h)

add_library(tc SHARED ${SOURCE_FILES})
message(tc ${GMP_LIBRARIES} ${MHASH_LIBRARIES} ${CHECK_LIBRARIES})
target_link_libraries(tc ${GMP_LIBRARIES} ${MHASH_LIBRARIES} ${CHECK_LIBRARIES})


add_executable(check_algorithms check_algorithms.c)
target_link_libraries(check_algorithms tc)

add_executable(main main.c)
target_link_libraries(main tc)
