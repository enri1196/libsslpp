#pragma once

#include <cstring>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "bio.hpp"
#include "evp_pkey/base_pkey.hpp"

namespace openssl::key {

enum class RsaKeyBits : std::int32_t {
  RSA_1024 = 1024,
  RSA_2048 = 2048,
  RSA_4096 = 4096,
};

class LIBSSLPP_PUBLIC RsaPublicKey : public BasePKey<Public> {
private:
  EVP_PKEY* m_key;

public:
  RsaPublicKey() = delete;
  RsaPublicKey(const RsaPublicKey&);
  RsaPublicKey(RsaPublicKey&&);
  RsaPublicKey& operator=(const RsaPublicKey&);
  RsaPublicKey& operator=(RsaPublicKey&&);
  virtual ~RsaPublicKey() override;

  explicit RsaPublicKey(EVP_PKEY* oth_key);

  auto as_ptr() const noexcept -> EVP_PKEY* override;

  auto to_string() const -> std::string override;
};

class LIBSSLPP_PUBLIC RsaKey : public BasePKey<Private> {
private:
  EVP_PKEY* m_key;

public:
  RsaKey() = delete;
  RsaKey(const RsaKey &);
  RsaKey(RsaKey &&);
  RsaKey &operator=(const RsaKey &);
  RsaKey &operator=(RsaKey &&);
  virtual ~RsaKey() override;

  explicit RsaKey(EVP_PKEY* oth_key);

  explicit RsaKey(const RsaKeyBits bits);

  auto as_ptr() const noexcept -> EVP_PKEY* override;

  auto to_string() const -> std::string override;

  auto get_public() const -> std::unique_ptr<BasePKey<Public>> override;

  auto sign(const std::vector<std::uint8_t>& data) const -> std::vector<std::uint8_t> override;
};

}
