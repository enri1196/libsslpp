cmake_minimum_required(VERSION 3.28)
project(sslpp_module CXX)

# Turning off extensions avoids an issue with the clang 16 compiler
# clang 17 and greater can avoid this setting
# set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
set(OPENSSL_USE_STATIC_LIBS TRUE)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wconversion -Wimplicit-fallthrough -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

find_package(OpenSSL REQUIRED)
add_library(sslpp)

# Add the module file to the library
target_sources(sslpp
  PUBLIC
    FILE_SET CXX_MODULES FILES
    src/asn1/asn1_mod.ixx
    src/asn1/cms_content_info.ixx
    src/asn1/asn1_integer.ixx
    src/asn1/asn1_time.ixx
    src/asn1/asn1_octet_string.ixx
    src/tsp/tsp_mod.ixx
    src/tsp/tsp_response.ixx
    src/tsp/tsp_request.ixx
    src/x509/x509_store.ixx
    src/x509/extensions/extended_key_usage.ixx
    src/x509/extensions/key_usage.ixx
    src/x509/x509_name.ixx
    src/x509/x509_req.ixx
    src/x509/x509_cert.ixx
    src/x509/x509_mod.ixx
    src/x509/x509_ext.ixx
    src/bio.ixx
    src/bignum.ixx
    src/base64.ixx
    src/cms.ixx
    src/evp_pkey.ixx
    src/ocsp/ocsp_response.ixx
    src/ocsp/ocsp_mod.ixx
    src/ocsp/ocsp_request.ixx
)

# Create an executable
add_executable(test_bin test/main.cxx)
# Link to the library foo
target_link_libraries(test_bin PRIVATE sslpp OpenSSL::SSL OpenSSL::Crypto)
