cmake_minimum_required(VERSION 3.10)

project(PASSWORDCRACKER CXX)

set(CMAKE_CXX_STANDARD 20)

include_directories(${CMAKE_SOURCE_DIR}/src)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cc")

add_executable(password-cracker main.cc ${SOURCES})