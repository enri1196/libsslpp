#include "gtest/gtest.h"

#include "evp_pkey/base_pkey.hpp"
#include "evp_pkey/ec_key.hpp"
#include "evp_pkey/rsa_key.hpp"

TEST(EVPPkey, generate_rsa) {
  using namespace openssl::key;
  const std::unique_ptr<BasePKey<Private>> rsa = std::make_unique<RsaKey>(RsaKeyBits::RSA_4096);

  std::cout << rsa->to_string() << "\n";
  EXPECT_TRUE(rsa != nullptr);
}

TEST(EVPPkey, generate_ec) {
  using namespace openssl::key;
  const std::unique_ptr<BasePKey<Private>> eckey = std::make_unique<EcKey>(EcKeyNid::SECP_521R1);

  std::cout << eckey->to_string() << "\n";
  EXPECT_TRUE(eckey != nullptr);
}

TEST(EVPPkey, get_public_key) {
  using namespace openssl::key;
  const std::unique_ptr<BasePKey<Private>> rsa = std::make_unique<RsaKey>(RsaKeyBits::RSA_4096);

  const auto pub_key = rsa->get_public();
  const auto str = pub_key->to_string();
  std::cout << str << "\n";
  EXPECT_EQ(pub_key != nullptr && !str.empty(), true);
}

TEST(EVPPkey, sign_data) {
  using namespace openssl::key;
  const std::unique_ptr<BasePKey<Private>> ec_key = std::make_unique<EcKey>(EcKeyNid::SECP_521R1);

  std::vector<std::uint8_t> data{1,5,3,2,5,7,8,5,4,3,2,5,7,8};
  auto sig = ec_key->sign(data);
  EXPECT_EQ(!sig.empty(), true);
}
