file(GLOB SOURCES "${CMAKE_SOURCE_DIR}/src/*.cc")

add_library(password-cracker-lib ${SOURCES})

target_include_directories(password-cracker-lib PUBLIC ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(password-cracker-lib -lcrypt OpenMP::OpenMP_CXX)
