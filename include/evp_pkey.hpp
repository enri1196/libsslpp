#pragma once

#include <concepts>
#include <vector>

#include "bio.hpp"

namespace openssl {

class Private {};
class Public {};

class Rsa {};
class EcKey {};

template<typename KeyType>
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
  explicit EVPPkey(EVP_PKEY *ptr,
                   std::function<void(EVP_PKEY *)> free_fn = EVP_PKEY_free)
      : m_ssl_type(ptr, free_fn) {}
  ~EVPPkey() = default;

  auto as_ptr() const noexcept -> EVP_PKEY* { return m_ssl_type.get(); }

  template<typename KeyAlgorithm>
  requires std::same_as<Rsa, KeyAlgorithm> && std::same_as<KeyType, Private>
  static auto generate(const std::int32_t bits = 2048) -> Expected<EVPPkey<Private>> {
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

  template<typename KeyAlgorithm>
  requires std::same_as<EcKey, KeyAlgorithm> && std::same_as<KeyType, Private>
  static auto generate(const std::int32_t nid = NID_secp521r1) -> Expected<EVPPkey<Private>> {
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

  auto get_public() const -> EVPPkey<Public>
  requires std::same_as<KeyType, Private>
  {
    auto bio = SSLBio::init();
    auto evp_ptr = this->as_ptr();
    EVP_PKEY_up_ref(this->as_ptr());
    PEM_write_bio_PUBKEY(bio.as_ptr(), evp_ptr);
    auto pub_key = PEM_read_bio_PUBKEY(bio.as_ptr(), &evp_ptr, nullptr, nullptr);
    return EVPPkey<Public>(pub_key, [](EVP_PKEY*){});
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
