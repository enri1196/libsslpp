#include "gtest/gtest.h"
#include <iostream>

#include "bio.hpp"

class SharedBIO {
private:
    openssl::SSLBio bio;

public:
    SharedBIO(openssl::SSLBio in_bio) : bio(in_bio) {}

    auto print_info() {
        std::cout << bio.get_mem_ptr().value() << "\n";
    }
};

TEST(SSLBio, shared_ref) {
    auto shared_bio = openssl::SSLBio::init();
    shared_bio.write_mem("/Users/enrico/Programming/libsslpp/test/test_files/google.cer");

    auto sb1 = SharedBIO(shared_bio);
    auto sb2 = SharedBIO(shared_bio);
    auto sb3 = SharedBIO(shared_bio);

    std::cout << shared_bio.get_mem_ptr().value() << "\n";
    sb1.print_info();
    sb2.print_info();
    sb3.print_info();

    SUCCEED();
}
