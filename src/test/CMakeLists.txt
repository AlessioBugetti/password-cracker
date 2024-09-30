include(GoogleTest)

enable_testing()

file(GLOB TESTS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/test/*.cc")

foreach(test_file ${TESTS})
  get_filename_component(test_name ${test_file} NAME_WE)
  add_executable(${test_name} ${test_file})
  target_link_libraries(${test_name} GTest::gtest_main password-cracker-lib)
  gtest_discover_tests(${test_name})
endforeach()
