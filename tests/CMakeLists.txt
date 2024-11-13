
set(TLIBS cppunit crypto_samples)
set(TDIR ${PROJECT_SOURCE_DIR}/tests)
set(TSRC ${TDIR}/main.cpp)
include_directories(${TDIR})

add_executable(Tests ${TDIR}/Tests.cpp ${TSRC})
target_link_libraries(Tests PUBLIC ${TLIBS})
target_compile_options(Tests PUBLIC ${TFLAGS})

add_test(NAME test COMMAND Tests)