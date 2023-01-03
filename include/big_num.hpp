#pragma once

#include <string_view>
#include <concepts>

#include <openssl/bn.h>

#include "internal/ssl_interface.hpp"

namespace openssl {

class Asn1Integer;

class LIBSSLPP_PUBLIC BigNum {
private:
  using SSLPtr = std::shared_ptr<BIGNUM>;
  SSLPtr m_ssl_type;

  BigNum() : m_ssl_type(BN_new(), BN_free) {}

public:
  BigNum(const BigNum &) = default;
  BigNum(BigNum &&) noexcept = default;
  auto operator=(const BigNum &) -> BigNum& = default;
  auto operator=(BigNum &&) noexcept -> BigNum& = default;
  explicit BigNum(BIGNUM *ptr) : m_ssl_type(ptr, BN_free) {}
  ~BigNum();

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
