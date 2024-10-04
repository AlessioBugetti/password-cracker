cmake_minimum_required(VERSION 3.13)

project(PASSWORDCRACKER CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(UNIX AND NOT APPLE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
elseif(APPLE)
  find_path(
    OPENMP_INCLUDE_DIR
    NAMES omp.h
    HINTS /usr/local/libomp/include
          /opt/homebrew/libomp/include
          /opt/homebrew/opt/libomp/include
          /opt/local/libomp/include
          /usr/local/Cellar/libomp/include
          /usr/libomp/include
          /usr/local/libomp/*/include
          /opt/homebrew/libomp/*/include
          /opt/homebrew/opt/libomp/*/include
          /opt/local/libomp/*/include
          /usr/local/Cellar/libomp/*/include
          /usr/libomp/*/include)

  find_path(
    OPENMP_LIBRARY
    NAMES libomp.a libomp.dylib
    HINTS /usr/local/libomp/lib
          /opt/homebrew/libomp/lib
          /opt/homebrew/opt/libomp/lib
          /opt/local/libomp/lib
          /usr/local/Cellar/libomp/lib
          /usr/libomp/lib
          /usr/local/libomp/*/lib
          /opt/homebrew/libomp/*/lib
          /opt/homebrew/opt/libomp/*/lib
          /opt/local/libomp/*/lib
          /usr/local/Cellar/libomp/*/lib
          /usr/libomp/*/lib)

  if(OPENMP_INCLUDE_DIR AND OPENMP_LIBRARY)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Xpreprocessor -fopenmp")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L${OPENMP_LIBRARY} -lomp")
    include_directories(${OPENMP_INCLUDE_DIR})
  else()
    message(FATAL_ERROR "OpenMP not found")
  endif()
else()
  message(FATAL_ERROR "Unsupported operating system. This project supports only macOS and Linux")
endif()

include_directories(${CMAKE_SOURCE_DIR}/src)

add_subdirectory(src)
add_subdirectory(benchmarks)
add_subdirectory(src/test)

add_executable(main main.cc)
target_link_libraries(main PRIVATE password-cracker-lib)
if(UNIX AND NOT APPLE)
  target_link_libraries(main PRIVATE -lcrypt)
endif()
