cmake_minimum_required (VERSION 2.6)
project (lthread)
SET(CMAKE_C_FLAGS "-std=gnu99 -pipe -fPIC  -Werror -Wall -Wformat=1 -Wformat-security -Wtype-limits -Wmultichar -Wuninitialized")
SET(CMAKE_C_FLAGS_RELEASE "-O3 -fomit-frame-pointer")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g3 -fno-inline-functions")
#SET(CMAKE_VERBOSE_MAKEFILE "on")

# maybe i got this wrong, but looks like a cmake bug
# without this 'set', option will be constantly on :\
SET(SOCKET_PASSTHROUGH "OFF")
option(SOCKET_PASSTHROUGH "lthread socket functions passthrough feature" OFF)

if(SOCKET_PASSTHROUGH)
  add_definitions(-DLTHREAD_SOCKET_PASSTHROUGH)
endif(SOCKET_PASSTHROUGH)
message("Socket functions passthrough feature ${SOCKET_PASSTHROUGH}")

SET(SOCKET_TIMEO "OFF")
option(SOCKET_TIMEO "lthread socket functions timeout feature" OFF)

if(SOCKET_TIMEO)
  add_definitions(-DLTHREAD_TIMEOUT_FROM_SOCKET)
endif(SOCKET_TIMEO)
message("Socket functions timeout feature ${SOCKET_TIMEO}")


set(lthread_files src/lthread.c src/lthread_socket.c
                  src/lthread_sched.c src/lthread_io.c
                  src/lthread_poller.c src/lthread_compute.c
                  src/cfuhash/cfuhash.c)
add_library(lthread  ${lthread_files})

install(TARGETS lthread DESTINATION lib)
install(FILES src/lthread.h DESTINATION include)

set(UNIT_TEST_PATH ${CMAKE_BINARY_DIR}/tests)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${UNIT_TEST_PATH})
include_directories(src)

add_executable(lthread_sleep tests/lthread_sleep.c)
target_link_libraries(lthread_sleep lthread pthread)

add_executable(lthread_io tests/lthread_io.c)
target_link_libraries(lthread_io lthread pthread)

add_executable(lthread_join tests/lthread_join.c)
target_link_libraries(lthread_join  lthread pthread)

add_executable(lthread_poll tests/lthread_poll.c)
target_link_libraries(lthread_poll  lthread pthread)

add_executable(lthread_fdeof_read tests/lthread_fdeof_read.c)
target_link_libraries(lthread_fdeof_read  lthread pthread)

add_executable(lthread_fdeof_write tests/lthread_fdeof_write.c)
target_link_libraries(lthread_fdeof_write  lthread pthread)

enable_testing()
add_test(lthread_sleep ${UNIT_TEST_PATH}/lthread_sleep)
add_test(lthread_join ${UNIT_TEST_PATH}/lthread_join)
add_test(lthread_poll ${UNIT_TEST_PATH}/lthread_poll)
add_test(lthread_fdeof_read ${UNIT_TEST_PATH}/lthread_fdeof_read)
add_test(lthread_fdeof_write ${UNIT_TEST_PATH}/lthread_fdeof_write)
