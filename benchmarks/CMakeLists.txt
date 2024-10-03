file(GLOB BENCH_FILES "*.cc")

foreach(BENCH_FILE ${BENCH_FILES})
  get_filename_component(BENCH_NAME ${BENCH_FILE} NAME_WE)
  add_executable(${BENCH_NAME} ${BENCH_FILE})
  target_include_directories(${BENCH_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(${BENCH_NAME} PRIVATE password-cracker-lib)
endforeach()
