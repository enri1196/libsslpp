module;

#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

using namespace std;

export module evp;

import bio;

namespace openssl::key {

export enum class EcCurves : int32_t {
  SECP_112R1 = NID_secp112r1,
  SECP_112R2 = NID_secp112r2,
  SECP_128R1 = NID_secp128r1,
  SECP_128R2 = NID_secp128r2,
  SECP_256K1 = NID_secp256k1,
  SECP_521R1 = NID_secp521r1,
  X25519 = NID_X25519,
  ED448 = NID_Ed448,
};

export enum class Rsa {
  R1024_BITS = 1024,
  R2048_BITS = 2048,
  R4096_BITS = 4096,
};

static void evp_own_free(EVP_PKEY *x) { EVP_PKEY_free(x); }
static void evp_ref_free(EVP_PKEY *x) {}

export struct Private {};
export struct Public {};

export template <typename KeyType>
  requires same_as<KeyType, Private> || same_as<KeyType, Public>
class EvpPKey {};

export template <> class EvpPKey<Public> {
private:
  shared_ptr<EVP_PKEY> m_ssl_type;

  EvpPKey() = delete;
  explicit EvpPKey(EVP_PKEY *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &evp_own_free : &evp_ref_free) {}

public:
  static auto own(EVP_PKEY *ref) -> EvpPKey { return EvpPKey(ref); }
  static auto ref(EVP_PKEY *ref) -> EvpPKey { return EvpPKey(ref, false); }

  static auto from(bio::SSLBio &&bio) -> EvpPKey {
    auto key = d2i_PUBKEY_bio(bio.as_ptr(), nullptr);
    if (key == nullptr) {
      throw runtime_error("EvpPKey conversion from BIO Error");
    }
    return EvpPKey(key);
  }

  static auto from(span<uint8_t> &&bytes) -> EvpPKey {
    const unsigned char *data = bytes.data();
    auto key = d2i_PUBKEY(nullptr, &data, bytes.size());
    if (key == nullptr) {
      throw runtime_error("EvpPKey conversion from bytes Error");
    }
    return EvpPKey(key);
  }

  auto as_ptr() const noexcept -> EVP_PKEY * { return m_ssl_type.get(); }

  auto to_string() const -> string {
    auto bio = bio::SSLBio::memory();
    PEM_write_bio_PUBKEY(bio.as_ptr(), this->as_ptr());
    return bio.get_mem_ptr();
  }
};

export template <> class EvpPKey<Private> {
private:
  shared_ptr<EVP_PKEY> m_ssl_type;

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

  static auto from(bio::SSLBio &&bio) -> EvpPKey {
    auto key = d2i_PrivateKey_bio(bio.as_ptr(), nullptr);
    if (key == nullptr) {
      throw runtime_error("EvpPKey conversion from BIO Error");
    }
    return EvpPKey(key);
  }

  static auto from(span<uint8_t> &&bytes) -> EvpPKey {
    const unsigned char *data = bytes.data();
    auto key = d2i_AutoPrivateKey(nullptr, &data, bytes.size());
    if (key == nullptr) {
      throw runtime_error("EvpPKey conversion from bytes Error");
    }
    return EvpPKey(key);
  }

  auto clone() -> EvpPKey {
    auto clone = EVP_PKEY_up_ref(this->as_ptr());
    return EvpPKey(this->as_ptr());
  }

  auto as_ptr() const noexcept -> EVP_PKEY * { return m_ssl_type.get(); }

  auto to_string() const -> string {
    auto bio = bio::SSLBio::memory();
    PEM_write_bio_PrivateKey(bio.as_ptr(), this->as_ptr(), nullptr, nullptr, 0,
                             nullptr, nullptr);
    return bio.get_mem_ptr();
  }

  auto get_public() const -> EvpPKey<Public> {
    auto bio = bio::SSLBio::memory();
    auto evp_ptr = this->as_ptr();
    PEM_write_bio_PUBKEY(bio.as_ptr(), evp_ptr);
    auto pub_key =
        PEM_read_bio_PUBKEY(bio.as_ptr(), &evp_ptr, nullptr, nullptr);
    return EvpPKey<Public>::ref(pub_key);
  }

  auto sign(span<uint8_t> &&data) const
      -> vector<uint8_t> {
    auto ctx = EVP_PKEY_CTX_new(this->as_ptr(), nullptr);
    EVP_PKEY_sign_init(ctx);
    size_t sig_len = 0;
    auto sig_data = vector<uint8_t>();
    EVP_PKEY_sign(ctx, sig_data.data(), &sig_len, data.data(), data.size());
    EVP_PKEY_CTX_free(ctx);
    return sig_data;
  }
};

} // namespace openssl::key
