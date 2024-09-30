cmake_minimum_required(VERSION 3.10)

project(PASSWORDCRACKER CXX)

set(CMAKE_CXX_STANDARD 20)

include_directories(${CMAKE_SOURCE_DIR}/src)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cc")

add_executable(password-cracker main.cc ${SOURCES})

file(GLOB BENCHMARKS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/benchmarks/*.cc")

foreach(benchmark_file ${BENCHMARKS})
    get_filename_component(benchmark_name ${benchmark_file} NAME_WE)
    add_executable(${benchmark_name} ${benchmark_file} ${SOURCES})
endforeach()