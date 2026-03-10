cmake_minimum_required(VERSION 3.16)
project(dnstunnel C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-D_GNU_SOURCE)
add_compile_options(-Wall -Wextra -Werror -pedantic)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)
pkg_check_modules(CARES REQUIRED libcares)
pkg_check_modules(LZ4 REQUIRED liblz4)

# Common library
file(GLOB COMMON_SOURCES common/*.c)
add_library(common_lib STATIC ${COMMON_SOURCES} third_party/lz4.c)
target_include_directories(common_lib PUBLIC common third_party
    ${LIBUV_INCLUDE_DIRS} ${CARES_INCLUDE_DIRS} ${LZ4_INCLUDE_DIRS})
target_link_libraries(common_lib
    ${LIBUV_LIBRARIES} ${CARES_LIBRARIES} ${LZ4_LIBRARIES} m)

# Client binary
add_executable(dnstunnel-client
    client/main.c client/socks5.c client/tunnel_client.c client/check.c)
target_include_directories(dnstunnel-client PRIVATE
    common third_party ${LIBUV_INCLUDE_DIRS} ${CARES_INCLUDE_DIRS})
target_link_libraries(dnstunnel-client common_lib)

# Server binary
add_executable(dnstunnel-server
    server/main.c server/dns_server.c server/tunnel_server.c server/proxy.c)
target_include_directories(dnstunnel-server PRIVATE
    common third_party ${LIBUV_INCLUDE_DIRS} ${CARES_INCLUDE_DIRS})
target_link_libraries(dnstunnel-server common_lib)

# Tests
enable_testing()
foreach(test_src
    tests/test_encode.c
    tests/test_transport.c
    tests/test_dns_packet.c)
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src})
    target_include_directories(${test_name} PRIVATE
        common third_party ${LIBUV_INCLUDE_DIRS} ${CARES_INCLUDE_DIRS})
    target_link_libraries(${test_name} common_lib)
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
