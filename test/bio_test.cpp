#include "gtest/gtest.h"
#include <cstring>
#include <iostream>
#include <memory>

#include "bio.hpp"
#include "internal/ssl_interface.hpp"
#include "openssl/bio.h"

using namespace openssl;

class SharedSslBIO {
private:
    std::shared_ptr<SSLBio> bio;

public:
    SharedSslBIO(std::shared_ptr<SSLBio> bio) : bio(std::move(bio)) {}
    auto as_ptr() const noexcept -> BIO * { return bio->as_ptr(); }

    auto get_str() const -> std::string {
        return bio->get_mem_ptr();
    }
};

TEST(SSLBio, shared_bio) {
    auto shared_bio = std::make_shared<SSLBio>();
    shared_bio->write_mem("Some random data to write");

    {
        auto sb1 = SharedSslBIO(shared_bio);
        auto curr_data = sb1.get_str();
        EXPECT_EQ(curr_data, "Some random data to write");
    }
    {
        auto sb2 = SharedSslBIO(shared_bio);
        auto curr_data = sb2.get_str();
        EXPECT_EQ(curr_data, "Some random data to write");
    }
    {
        auto sb3 = SharedSslBIO(shared_bio);
        auto curr_data = sb3.get_str();
        EXPECT_EQ(curr_data, "Some random data to write");
    }

}
