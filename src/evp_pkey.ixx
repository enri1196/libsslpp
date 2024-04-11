module;

#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

using namespace std;

export module evp;

import bio;

namespace openssl::key {

export enum class EcCurves : int32_t {
  SECP_112R1  = NID_secp112r1,
  SECP_112R2  = NID_secp112r2,
  SECP_128R1  = NID_secp128r1,
  SECP_128R2  = NID_secp128r2,
  SECP_256K1  = NID_secp256k1,
  SECP_521R1  = NID_secp521r1,
  X25519      = NID_X25519,
  ED448       = NID_Ed448,
};

export enum class Rsa : int32_t {
  R1024_BITS = 1024,
  R2048_BITS = 2048,
  R4096_BITS = 4096,
};

static void evp_own_free(EVP_PKEY *x) { EVP_PKEY_free(x); }
static void evp_ref_free(EVP_PKEY *) {}

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
      throw runtime_error("EvpPKey Public conversion from BIO Error");
    }
    return EvpPKey(key);
  }

  static auto from(span<uint8_t> &&bytes) -> EvpPKey {
    const unsigned char *data = bytes.data();
    auto key = d2i_PUBKEY(nullptr, &data, (long)bytes.size());
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
    EVP_PKEY_CTX *evp_ctx = nullptr;
    switch (nid) {
    case EcCurves::X25519:
      evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
      break;
    // case EcCurves::ED448:  // error x448 doesn't exist
    //   evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr);
    //   break;
    default:
      evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    }
    EVP_PKEY_keygen_init(evp_ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx, (int32_t)nid);
    EVP_PKEY_keygen(evp_ctx, &m_key);
    EVP_PKEY_CTX_free(evp_ctx);
    return EvpPKey(m_key);
  }

  static auto from(Rsa size) -> EvpPKey {
    auto m_key = EVP_PKEY_new();
    auto evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(evp_ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx, (int32_t)size);
    EVP_PKEY_keygen(evp_ctx, &m_key);
    EVP_PKEY_CTX_free(evp_ctx);
    return EvpPKey(m_key);
  }

  static auto from(bio::SSLBio &&bio) -> EvpPKey {
    auto key = d2i_PrivateKey_bio(bio.as_ptr(), nullptr);
    if (key == nullptr) {
      throw runtime_error("EvpPKey Private conversion from BIO Error");
    }
    return EvpPKey(key);
  }

  static auto from(span<uint8_t> &&bytes) -> EvpPKey {
    const unsigned char *data = bytes.data();
    auto key = d2i_AutoPrivateKey(nullptr, &data, (int64_t)bytes.size());
    if (key == nullptr) {
      throw runtime_error("EvpPKey Private conversion from bytes Error");
    }
    return EvpPKey(key);
  }

  auto as_ptr() const noexcept -> EVP_PKEY * { return m_ssl_type.get(); }

  auto to_string() const -> string {
    auto bio = bio::SSLBio::memory();
    PEM_write_bio_PrivateKey(bio.as_ptr(), this->as_ptr(), nullptr, nullptr, 0,
                             nullptr, nullptr);
    return bio.get_mem_ptr();
  }

  auto get_public() const -> EvpPKey<Public> {
    int key_type = EVP_PKEY_id(this->as_ptr());
    EVP_PKEY* public_key = EVP_PKEY_new();
    switch (key_type) {
      // --- RSA_KEY ---
      case EVP_PKEY_RSA: {
        RSA* rsa_key = EVP_PKEY_get1_RSA(this->as_ptr());
        if (rsa_key == nullptr) {
          throw runtime_error("Pkey write error");
        }
        if (!EVP_PKEY_set1_RSA(public_key, rsa_key)) {
          RSA_free(rsa_key);
          EVP_PKEY_free(public_key);
          throw runtime_error("Pkey write error");
        }
        RSA_free(rsa_key);
        break;
      }
      // --- EC_KEY ---
      case EVP_PKEY_EC: {
        EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(this->as_ptr());
        if (ec_key == nullptr) {
          throw runtime_error("Pkey write error");
        }
        if (!EVP_PKEY_set1_EC_KEY(public_key, ec_key)) {
          EC_KEY_free(ec_key);
          EVP_PKEY_free(public_key);
          throw runtime_error("Pkey write error");
        }
        EC_KEY_free(ec_key);
        break;
      }
      // --- X25519 ---
      case EVP_PKEY_X25519: {
        size_t keylen = 0;
        if (EVP_PKEY_get_raw_public_key(this->as_ptr(), nullptr, &keylen) != 1) {
          EVP_PKEY_free(public_key);
          throw runtime_error("Pkey write error");
        }
        vector<uint8_t> raw_key(keylen);
        if (EVP_PKEY_get_raw_public_key(this->as_ptr(), raw_key.data(), &keylen) != 1) {
          EVP_PKEY_free(public_key);
          throw runtime_error("Pkey write error");
        }
        public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, raw_key.data(), keylen);
        if (public_key == nullptr) {
          throw runtime_error("Pkey write error");
        }
        break;
      }
    }
    return EvpPKey<Public>::own(public_key);
  }

  auto sign(span<uint8_t> &&data) const -> vector<uint8_t> {
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
