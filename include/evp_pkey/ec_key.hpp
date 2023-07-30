#pragma once

#include <cstring>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "bio.hpp"
#include "evp_pkey/base_pkey.hpp"

namespace openssl::key {

enum class EcKeyNid;

class LIBSSLPP_PUBLIC EcPublicKey : public BasePKey<Public> {
private:
  EVP_PKEY* m_key;

public:
  EcPublicKey() = delete;
  EcPublicKey(const EcPublicKey&);
  EcPublicKey(EcPublicKey&&);
  EcPublicKey& operator=(const EcPublicKey&);
  EcPublicKey& operator=(EcPublicKey&&);
  virtual ~EcPublicKey() override;

  explicit EcPublicKey(EVP_PKEY* oth_key);

  auto as_ptr() const noexcept -> EVP_PKEY* override;

  auto to_string() const -> std::string override;
};

class LIBSSLPP_PUBLIC EcKey : public BasePKey<Private> {
private:
  EVP_PKEY* m_key;

public:
  EcKey() = delete;
  EcKey(const EcKey &);
  EcKey(EcKey &&);
  EcKey &operator=(const EcKey &);
  EcKey &operator=(EcKey &&);
  virtual ~EcKey() override;

  explicit EcKey(EVP_PKEY* oth_key);

  explicit EcKey(const EcKeyNid nid);

  auto as_ptr() const noexcept -> EVP_PKEY* override;

  auto to_string() const -> std::string override;

  auto get_public() const -> std::unique_ptr<BasePKey<Public>> override;

  auto sign(const std::vector<std::uint8_t>& data) const -> std::vector<std::uint8_t> override;
};

enum class EcKeyNid : std::int32_t {
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
// NID_secp256k1
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
};

}
