cmake_minimum_required(VERSION 3.28)
project(sslpp_module CXX)

# Turning off extensions avoids an issue with the clang 16 compiler
# clang 17 and greater can avoid this setting
set(CMAKE_CXX_EXTENSIONS OFF)
# Set the version of C++ for the project
set(CMAKE_CXX_STANDARD 23)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
add_library(sslpp)

file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_SOURCE_DIR} "src/*.ixx")

# Add the module file to the library
target_sources(sslpp
  PUBLIC
    FILE_SET CXX_MODULES FILES
    #   src/*.ixx
    ${SOURCES}
)
# Create an executable
add_executable(test_bin main.cxx)
# Link to the library foo
target_link_libraries(test_bin PRIVATE sslpp OpenSSL::applink)
