#include "gtest/gtest.h"
#include <iostream>

#include "bio.hpp"

class SharedBIO {
private:
    openssl::SSLBio bio;

public:
    SharedBIO(openssl::SSLBio in_bio) : bio(in_bio) {}

    auto get_str() -> std::string_view {
        return bio.get_mem_ptr().value();
    }
};

TEST(SSLBio, shared_ref) {
    auto shared_bio = openssl::SSLBio::init();
    shared_bio.write_mem("Some random data to write");

    auto sb1 = SharedBIO(shared_bio);
    auto sb2 = SharedBIO(shared_bio);
    auto sb3 = SharedBIO(shared_bio);

    EXPECT_EQ(sb1.get_str(), "Some random data to write");
    EXPECT_EQ(sb2.get_str(), "Some random data to write");
    EXPECT_EQ(sb3.get_str(), "Some random data to write");
}
