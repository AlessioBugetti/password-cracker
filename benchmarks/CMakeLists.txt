file(GLOB BENCHMARKS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/benchmarks/*.cc")

foreach(benchmark_file ${BENCHMARKS})
  get_filename_component(benchmark_name ${benchmark_file} NAME_WE)
  add_executable(${benchmark_name} ${benchmark_file})
  target_link_libraries(${benchmark_name} PRIVATE password-cracker-lib)
  target_link_libraries(${benchmark_name} PRIVATE OpenMP::OpenMP_CXX)
endforeach()
