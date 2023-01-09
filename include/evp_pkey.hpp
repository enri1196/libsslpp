#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>

#include "bio.hpp"

namespace openssl {

class Private {};
class Public {};

class Rsa {};
class EcKey {};

template<class KeyType>
requires std::same_as<Private, KeyType> || std::same_as<Public, KeyType>
class EVPPkey {
private:
  using SSLPtr = std::shared_ptr<EVP_PKEY>;
  SSLPtr m_ssl_type;

  EVPPkey() : m_ssl_type(EVP_PKEY_new(), EVP_PKEY_free) {}

public:
  EVPPkey(const EVPPkey &) = default;
  EVPPkey(EVPPkey &&) noexcept = default;
  auto operator=(const EVPPkey &) -> EVPPkey& = default;
  auto operator=(EVPPkey &&) noexcept -> EVPPkey& = default;
  explicit EVPPkey(EVP_PKEY *ptr) : m_ssl_type(ptr, EVP_PKEY_free) {}
  ~EVPPkey() = default;

  auto as_ptr() const noexcept -> EVP_PKEY* { return m_ssl_type.get(); }

  template<class KeyAlgorithm>
  requires std::same_as<Rsa, KeyAlgorithm> && std::same_as<KeyType, Private>
  static auto generate(std::size_t key_len = 2048) -> Expected<EVPPkey<Private>> {
    auto evp = EVPPkey();
    RSA* rsa = RSA_generate_key(static_cast<int>(key_len), RSA_F4, nullptr, nullptr);
    if (!EVP_PKEY_assign_RSA(evp.as_ptr(), rsa)) {
      return Unexpected(SSLError(ErrorCode::KeyGen));
    }
    return {evp};
  }

  template<class KeyAlgorithm>
  requires std::same_as<EcKey, KeyAlgorithm> && std::same_as<KeyType, Private>
  static auto generate(int nid_group = NID_secp521r1) -> Expected<EVPPkey<Private>> {
    auto evp = EVPPkey();
    EC_KEY* ec_key = EC_KEY_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid_group);
    if (EC_KEY_set_group(ec_key, group) != 1) {
      return Unexpected(SSLError(ErrorCode::KeyGen));
    }
    if (EC_KEY_generate_key(ec_key) != 1) {
      return Unexpected(SSLError(ErrorCode::KeyGen));
    }
    if (!EVP_PKEY_assign_EC_KEY(evp.as_ptr(), ec_key)) {
      return Unexpected(SSLError(ErrorCode::KeyGen));
    }
    return {evp};
  }

  auto to_string() const -> Expected<std::string_view> {
    auto bio = openssl::SSLBio::init();
    PEM_write_bio_PUBKEY(bio.as_ptr(), this->as_ptr());
    return bio.get_mem_ptr();
  }
};

}  // namespace openssl
