cmake_minimum_required(VERSION 3.16)
project(crypto_samples)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(INCLUDES ${INCLUDES} include)

include_directories(${INCLUDES})
file(GLOB_RECURSE SOURCE_FILES src/*.cpp)

## Packages
find_package(PkgConfig REQUIRED)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost REQUIRED COMPONENTS program_options)
set(LIBS ${LIBS} ${Boost_LIBRARIES})
set(INCLUDES ${INCLUDES} ${Boost_INCLUDE_DIRS})

pkg_check_modules(ZSTD REQUIRED libzstd)
set(LIBS ${LIBS} ${ZSTD_LIBRARIES})
set(INCLUDES ${INCLUDES} ${ZSTD_INCLUDE_DIRS})

pkg_check_modules(GPGME REQUIRED gpgme)
set(LIBS ${LIBS} ${GPGME_LIBRARIES})
set(INCLUDES ${INCLUDES} ${GPGME_INCLUDE_DIRS})

pkg_check_modules(FMT REQUIRED fmt)
set(LIBS ${LIBS} ${FMT_LIBRARIES})
set(INCLUDES ${INCLUDES} ${FMT_INCLUDE_DIRS})

pkg_check_modules(XMLPP REQUIRED libxml++-2.6)
set(LIBS ${LIBS} ${XMLPP_LIBRARIES})
set(INCLUDES ${INCLUDES} SYSTEM ${XMLPP_INCLUDE_DIRS})

find_package(LibArchive REQUIRED)
set(LIBS ${LIBS} ${LibArchive_LIBRARIES})
set(INCLUDES ${INCLUDES} ${LibArchive_INCLUDE_DIR})

find_package(OpenSSL REQUIRED)
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})
set(INCLUDES ${INCLUDES} ${OPENSSL_INCLUDE_DIR})

set(LIBS ${LIBS} stdc++fs)

set(LIBS ${LIBS} cppunit)

##

## Cpp Unit

# find cppunit
pkg_check_modules(CPPUNIT REQUIRED cppunit)

# add cppunit includes
set(INCLUDES ${INCLUDES} ${CPPUNIT_INCLUDE_DIRS})

# set test dir
set(TDIR ${PROJECT_SOURCE_DIR}/tests)

# set compile flags
set(TFLAGS ${CPPUNIT_CFLAGS} ${CPPUNIT_CFLAGS_OTHER})

# add test includes
set(INCLUDES ${INCLUDES} ${TDIR}/include)

# include stuff lol
include_directories(${INCLUDES})

##

add_library(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} ${LIBS})

enable_testing()
add_subdirectory(tests)