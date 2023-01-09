#pragma once

#include <string_view>
#include <concepts>

#include <openssl/bn.h>

#include "internal/ssl_interface.hpp"

namespace openssl {

class Asn1Integer;

class BigNum {
private:
  struct SSLDeleter {
    auto operator()(BIGNUM* ptr) { BN_free(ptr); }
  };
  using SSLPtr = std::unique_ptr<BIGNUM, SSLDeleter>;
  SSLPtr m_ssl_type;

  BigNum() : m_ssl_type(BN_new()) {}

public:
  BigNum(const BigNum &) = delete;
  BigNum(BigNum &&) noexcept = default;
  auto operator=(const BigNum &) -> BigNum& = delete;
  auto operator=(BigNum &&) noexcept -> BigNum& = default;
  explicit BigNum(BIGNUM *ptr) : m_ssl_type(ptr) {}
  ~BigNum() = default;

  auto as_ptr() const noexcept -> BIGNUM* { return m_ssl_type.get(); }

  template<class Asn1Int>
  requires std::same_as<Asn1Integer, Asn1Int>
  static auto from(const Asn1Int&& asn1_int) -> Expected<BigNum> {
    auto bn = ASN1_INTEGER_to_BN(asn1_int.as_ptr(), nullptr);
    if (bn == nullptr) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return {BigNum(bn)};
  }

  auto to_string() const -> Expected<std::string_view> {
    return {BN_bn2dec(this->as_ptr())};
  }
};

}  // namespace openssl
