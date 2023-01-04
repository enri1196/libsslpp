#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

#include "gtest/gtest.h"

#include "evp_pkey.hpp"

TEST(EVPPkey, generate_rsa) {
  const auto rsa = openssl::EVPPkey::generate_rsa();
  if (!rsa.has_value()) {
    std::cout << rsa.error() << "\n";
    FAIL();
  }
  std::cout << rsa->to_string().value() << "\n";
  EXPECT_EQ(rsa.has_value(), true);
}

TEST(EVPPkey, generate_eckey) {
  const auto ec_key = openssl::EVPPkey::generate_eckey();
  if (!ec_key.has_value()) {
    std::cout << ec_key.error() << "\n";
    FAIL();
  }
  std::cout << ec_key->to_string().value() << "\n";
  EXPECT_EQ(ec_key.has_value(), true);
}
