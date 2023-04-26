#pragma once

#include <concepts>
#include <iostream>
#include <vector>

#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/ec.h"
#include "openssl/pem.h"

#include "bio.hpp"

namespace openssl {

class Private {};
class Public {};

class Rsa {};
class EcKey {};

template<typename KeyType>
requires std::same_as<Private, KeyType> || std::same_as<Public, KeyType>
class LIBSSLPP_PUBLIC EVPPkey {
private:
  EVP_PKEY* m_ssl_type;

  EVPPkey() : m_ssl_type(EVP_PKEY_new()) {}

public:
  EVPPkey(const EVPPkey& key) {
    EVP_PKEY_up_ref(key.as_ptr());
    m_ssl_type = key.m_ssl_type;
  }
  EVPPkey(EVPPkey&& key) noexcept {
    m_ssl_type = key.m_ssl_type;
    key = nullptr;
  }
  auto operator=(const EVPPkey& key) -> EVPPkey& {
    if (this != &key) {
      EVP_PKEY_up_ref(key.as_ptr());
      m_ssl_type = key.m_ssl_type;
    }
    return *this;
  }
  auto operator=(EVPPkey&& key) noexcept -> EVPPkey& {
    if (this != &key) {
      m_ssl_type = key.m_ssl_type;
      key.m_ssl_type = nullptr;
    }
    return *this;
  }
  EVPPkey(EVP_PKEY* key) : m_ssl_type(key) {}
  ~EVPPkey() { EVP_PKEY_free(m_ssl_type); }

  auto as_ptr() const noexcept -> EVP_PKEY* { return m_ssl_type; }

  template<typename KeyAlgorithm>
  requires std::same_as<Rsa, KeyAlgorithm> && std::same_as<KeyType, Private>
  static auto generate(const std::int32_t bits = 2048) -> Expected<EVPPkey<Private>> {
    auto evp = EVP_PKEY_new();
    auto evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(evp_ctx);
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx, bits) <= 0) {
      EVP_PKEY_CTX_free(evp_ctx);
      return Unexpected(SSLError(ErrorCode::KeyGen));
    }
    EVP_PKEY_keygen(evp_ctx, &evp);
    EVP_PKEY_CTX_free(evp_ctx);
    return {EVPPkey<Private>(evp)};
  }

  template<typename KeyAlgorithm>
  requires std::same_as<EcKey, KeyAlgorithm> && std::same_as<KeyType, Private>
  static auto generate(const std::int32_t nid = NID_secp521r1) -> Expected<EVPPkey<Private>> {
    auto evp = EVP_PKEY_new();
    auto evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(evp_ctx);
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx, nid) <= 0) {
      EVP_PKEY_CTX_free(evp_ctx);
      return Unexpected(SSLError(ErrorCode::KeyGen));
    }
    EVP_PKEY_keygen(evp_ctx, &evp);
    EVP_PKEY_CTX_free(evp_ctx);
    return {EVPPkey<Private>(evp)};
  }

  auto get_public() const -> EVPPkey<Public>
  requires std::same_as<KeyType, Private>
  {
    auto bio = SSLBio::init();
    auto evp_ptr = this->as_ptr();
    EVP_PKEY_up_ref(this->as_ptr());
    PEM_write_bio_PUBKEY(bio.as_ptr(), evp_ptr);
    auto pub_key = PEM_read_bio_PUBKEY(bio.as_ptr(), &evp_ptr, nullptr, nullptr);
    return EVPPkey<Public>(pub_key);
  }

  auto sign(const std::vector<std::uint8_t>&& bytes) const -> std::vector<std::uint8_t>
  requires std::same_as<KeyType, Private>
  {
    auto ctx = EVP_PKEY_CTX_new(this->as_ptr(), nullptr);
    EVP_PKEY_sign_init(ctx);
    std::size_t sig_len = 0;
    EVP_PKEY_sign(ctx, nullptr, &sig_len, bytes.data(), bytes.size());
    std::vector<std::uint8_t> sig{};
    sig.reserve(sig_len);
    sig.resize(sig_len);
    EVP_PKEY_sign(ctx, sig.data(), &sig_len, bytes.data(), bytes.size());
    return sig;
  }

  auto to_string() const -> Expected<std::string_view>
  requires std::same_as<KeyType, Public>
  {
    auto bio = openssl::SSLBio::init();
    PEM_write_bio_PUBKEY(bio.as_ptr(), this->as_ptr());
    return bio.get_mem_ptr();
  }

  auto to_string() const -> Expected<std::string_view>
  requires std::same_as<KeyType, Private>
  {
    auto bio = openssl::SSLBio::init();
    PEM_write_bio_PrivateKey(bio.as_ptr(), this->as_ptr(), nullptr, nullptr, 0, nullptr, nullptr);
    return bio.get_mem_ptr();
  }
};

}  // namespace openssl
