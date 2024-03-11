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

# Add the module file to the library
target_sources(sslpp
  PUBLIC
    FILE_SET CXX_MODULES FILES
    src/asn1/asn1_mod.ixx
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
    src/evp_pkey.ixx
    src/ocsp/ocsp_response.ixx
    src/ocsp/ocsp_mod.ixx
    src/ocsp/ocsp_request.ixx
)
# Create an executable
add_executable(test_bin src/main.cxx)
# Link to the library foo
target_link_libraries(test_bin PRIVATE sslpp OpenSSL::SSL OpenSSL::Crypto)
