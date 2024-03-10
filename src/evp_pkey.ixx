module;

#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// #include "bio.hpp"

export module evp;

import bio;

namespace openssl::key {

enum class EcCurves : std::int32_t {
  SECP_112R1 = NID_secp112r1,
  SECP_112R2 = NID_secp112r2,
  SECP_128R1 = NID_secp128r1,
  SECP_128R2 = NID_secp128r2,
  // NID_secp160k1
  // NID_secp160r1
  // NID_secp160r2
  // NID_secp192k1
  // NID_secp224k1
  // NID_secp224r1
  SECP_256K1 = NID_secp256k1,
  // NID_secp384r1
  SECP_521R1 = NID_secp521r1,
  // NID_sect113r1
  // NID_sect113r2
  // NID_sect131r1
  // NID_sect131r2
  // NID_sect163k1
  // NID_sect163r1
  // NID_sect163r2
  // NID_sect193r1
  // NID_sect193r2
  // NID_sect233k1
  // NID_sect233r1
  // NID_sect239k1
  // NID_sect283k1
  // NID_sect283r1
  // NID_sect409k1
  // NID_sect409r1
  // NID_sect571k1
  // NID_sect571r1
  X25519 = NID_X25519,
  ED448 = NID_Ed448,
};

enum class Rsa {
  R1024_BITS = 1024,
  R2048_BITS = 2048,
  R4096_BITS = 4096,
};

static void evp_own_free(EVP_PKEY *x) { EVP_PKEY_free(x); }
static void evp_ref_free(EVP_PKEY *x) {}

struct Private {};
struct Public {};

export template <typename KeyType>
  requires std::same_as<KeyType, Private> || std::same_as<KeyType, Public>
class EvpPKey {};

export template <> class EvpPKey<Public> {
private:
  std::shared_ptr<EVP_PKEY> m_ssl_type;

  EvpPKey() = delete;
  explicit EvpPKey(EVP_PKEY *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &evp_own_free : &evp_ref_free) {}

public:
  static auto ref(EVP_PKEY *ref) -> EvpPKey { return EvpPKey(ref, false); }

  auto as_ptr() const noexcept -> EVP_PKEY * { return m_ssl_type.get(); }

  auto to_string() const -> std::string {
    auto bio = openssl::bio::SSLBio::memory();
    PEM_write_bio_PUBKEY(bio.as_ptr(), this->as_ptr());
    return bio.get_mem_ptr();
  }
};

export template <> class EvpPKey<Private> {
private:
  std::shared_ptr<EVP_PKEY> m_ssl_type;

  EvpPKey() = delete;
  explicit EvpPKey(EVP_PKEY *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &evp_own_free : &evp_ref_free) {}

public:
  static auto own(EVP_PKEY *ref) -> EvpPKey { return EvpPKey(ref); }
  static auto ref(EVP_PKEY *ref) -> EvpPKey { return EvpPKey(ref, false); }

  static auto from(EcCurves nid) -> EvpPKey {
    auto m_key = EVP_PKEY_new();
    auto evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(evp_ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx, (int)nid);
    EVP_PKEY_keygen(evp_ctx, &m_key);
    EVP_PKEY_CTX_free(evp_ctx);
    return EvpPKey(m_key);
  }

  static auto from(Rsa size) -> EvpPKey {
    auto m_key = EVP_PKEY_new();
    auto evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(evp_ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx, (int)size);
    EVP_PKEY_keygen(evp_ctx, &m_key);
    EVP_PKEY_CTX_free(evp_ctx);
    return EvpPKey(m_key);
  }

  auto clone() -> EvpPKey {
    auto clone = EVP_PKEY_up_ref(this->as_ptr());
    return EvpPKey(this->as_ptr());
  }

  auto as_ptr() const noexcept -> EVP_PKEY * { return m_ssl_type.get(); }

  auto to_string() const -> std::string {
    auto bio = openssl::bio::SSLBio::memory();
    PEM_write_bio_PrivateKey(bio.as_ptr(), this->as_ptr(), nullptr, nullptr, 0,
                             nullptr, nullptr);
    return bio.get_mem_ptr();
  }

  auto get_public() const -> EvpPKey<Public> {
    auto bio = openssl::bio::SSLBio::memory();
    auto evp_ptr = this->as_ptr();
    PEM_write_bio_PUBKEY(bio.as_ptr(), evp_ptr);
    auto pub_key =
        PEM_read_bio_PUBKEY(bio.as_ptr(), &evp_ptr, nullptr, nullptr);
    return EvpPKey<Public>::ref(pub_key);
  }

  auto sign(const std::vector<std::uint8_t> &data) const
      -> std::vector<std::uint8_t> {
    auto ctx = EVP_PKEY_CTX_new(this->as_ptr(), nullptr);
    EVP_PKEY_sign_init(ctx);
    std::size_t sig_len = 0;
    EVP_PKEY_sign(ctx, nullptr, &sig_len, data.data(), data.size());
    auto sig_data = std::vector<std::uint8_t>(sig_len);
    EVP_PKEY_sign(ctx, sig_data.data(), &sig_len, data.data(), data.size());
    EVP_PKEY_CTX_free(ctx);
    return sig_data;
  }
};

} // namespace openssl::key
