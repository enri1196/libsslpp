#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

#include "gtest/gtest.h"

#include "evp_pkey.hpp"

TEST(EVPPkey, generate_rsa) {
  const auto rsa = openssl::EVPPkey<openssl::Private>::generate<openssl::Rsa>();
  if (!rsa.has_value()) {
    std::cout << rsa.error() << "\n";
    FAIL();
  }
  std::cout << rsa->to_string().value() << "\n";
  EXPECT_EQ(rsa.has_value(), true);
}

TEST(EVPPkey, generate_eckey) {
  const auto ec_key = openssl::EVPPkey<openssl::Private>::generate<openssl::EcKey>();
  if (!ec_key.has_value()) {
    std::cout << ec_key.error() << "\n";
    FAIL();
  }
  std::cout << ec_key->to_string().value() << "\n";
  EXPECT_EQ(ec_key.has_value(), true);
}

TEST(EVPPkey, get_public_key) {
  const auto ec_key = openssl::EVPPkey<openssl::Private>::generate<openssl::EcKey>();
  if (!ec_key.has_value()) {
    std::cout << ec_key.error() << "\n";
    FAIL();
  }
  auto str = ec_key->get_public().to_string().value();
  std::cout << str << "\n";
  EXPECT_EQ(ec_key.has_value() && !str.empty(), true);
}

TEST(EVPPkey, sign_data) {
  const auto ec_key = openssl::EVPPkey<openssl::Private>::generate<openssl::EcKey>();
  if (!ec_key.has_value()) {
    std::cout << ec_key.error() << "\n";
    FAIL();
  }
  std::vector<std::uint8_t> bytes{1,5,3,2,5,7,8,5,4,3,2,5,7,8};
  auto sig = ec_key->sign(std::move(bytes));
  EXPECT_EQ(!sig.empty(), true);
}
