cmake_minimum_required(VERSION 2.8)

include_directories(${tclib_SOURCE_DIR}/include)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -g")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${tclib_SOURCE_DIR}/cmake)
include(FindGMP)
include(FindMHASH)

find_package(GMP REQUIRED)
message("gmp include ${GMP_INCLUDE_DIR}")
include_directories(${GMP_INCLUDE_DIRS})

find_package(MHASH REQUIRED)
include_directories(${MHASH_INCLUDE_DIR})

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
    poly.c
    random.c)

add_library(tc SHARED ${SOURCE_FILES} )
target_link_libraries(tc ${GMP_LIBRARIES} ${MHASH_LIBRARIES})
set_property(TARGET tc PROPERTY C_STANDARD 11)
set_property(TARGET tc PROPERTY C_STANDARD_REQUIRED_ON 11)

add_executable(main main.c)
target_link_libraries(main tc)
set_property(TARGET main PROPERTY C_STANDARD 11)
set_property(TARGET main PROPERTY C_STANDARD_REQUIRED_ON 11)


install(TARGETS tc DESTINATION lib)
install(FILES "${PROJECT_SOURCE_DIR}/include/tc.h" DESTINATION include)
