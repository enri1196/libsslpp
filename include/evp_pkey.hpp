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
#include "internal/ssl_interface.hpp"
#include "openssl/rsa.h"

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
  static auto generate(std::int32_t bits = 2048) -> Expected<EVPPkey<Private>> {
    auto evp = EVPPkey<Private>();
    auto evp_ptr = evp.as_ptr();
    auto evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(evp_ctx);
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx, bits) <= 0) {
      EVP_PKEY_CTX_free(evp_ctx);
      return Unexpected(SSLError(ErrorCode::KeyGen));
    }
    EVP_PKEY_keygen(evp_ctx, &evp_ptr);
    EVP_PKEY_CTX_free(evp_ctx);
    return {evp};
  }

  template<class KeyAlgorithm>
  requires std::same_as<EcKey, KeyAlgorithm> && std::same_as<KeyType, Private>
  static auto generate(std::int32_t nid = NID_secp521r1) -> Expected<EVPPkey<Private>> {
    auto evp = EVPPkey<Private>();
    auto evp_ptr = evp.as_ptr();
    auto evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(evp_ctx);
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx, nid) <= 0) {
      EVP_PKEY_CTX_free(evp_ctx);
      return Unexpected(SSLError(ErrorCode::KeyGen));
    }
    EVP_PKEY_keygen(evp_ctx, &evp_ptr);
    EVP_PKEY_CTX_free(evp_ctx);
    return {evp};
  }

  auto to_string() const -> Expected<std::string_view> {
    auto bio = openssl::SSLBio::init();
    PEM_write_bio_PUBKEY(bio.as_ptr(), this->as_ptr());
    return bio.get_mem_ptr();
  }
};

}  // namespace openssl
