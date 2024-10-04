file(GLOB SRC_FILES "*.cc")

add_library(password-cracker-lib STATIC ${SRC_FILES})

target_include_directories(password-cracker-lib PUBLIC ${PROJECT_SOURCE_DIR}/src)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if(UNIX AND NOT APPLE)
  find_package(OpenMP REQUIRED)
  target_link_libraries(password-cracker-lib PUBLIC -lcrypt OpenMP::OpenMP_CXX Threads::Threads)
else()
  target_link_libraries(password-cracker-lib PUBLIC OpenSSL::Crypto Threads::Threads)
endif()
