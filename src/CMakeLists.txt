file(GLOB SRC_FILES "*.cc")

add_library(password-cracker-lib STATIC ${SRC_FILES})

target_include_directories(password-cracker-lib PUBLIC ${PROJECT_SOURCE_DIR}/src)

if(UNIX AND NOT APPLE)
  find_package(OpenMP REQUIRED)
  target_link_libraries(password-cracker-lib PUBLIC -lcrypt OpenMP::OpenMP_CXX)
else()
  target_link_libraries(password-cracker-lib PUBLIC OpenSSL::Crypto)
endif()
