#include "big_num.hpp"

namespace openssl {
  BigNum::BigNum() : m_ssl_type(BN_new()) {}

  BigNum::BigNum(BigNum &&) noexcept = default;
  auto BigNum::operator=(BigNum &&) noexcept -> BigNum& = default;
  BigNum::BigNum(BIGNUM *ptr) : m_ssl_type(ptr) {}
  BigNum::~BigNum() = default;

  auto BigNum::operator<=>(const BigNum& other) noexcept -> std::strong_ordering {
    switch (BN_cmp(this->as_ptr(), other.as_ptr())) {
    case -1:
      return std::strong_ordering::less;
    case 0:
      return std::strong_ordering::equal;
    case 1:
      return std::strong_ordering::greater;
    default:
      return std::strong_ordering::equal; // shouldn't be reachable
    }
  }

  auto BigNum::as_ptr() const noexcept -> BIGNUM* {
    return m_ssl_type;
  }

  auto BigNum::from(const Asn1Integer&& asn1_int) -> Expected<BigNum> {
    auto bn = ASN1_INTEGER_to_BN(asn1_int.as_ptr(), nullptr);
    if (bn == nullptr) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return {BigNum(bn)};
  }

  auto BigNum::to_string() const -> Expected<std::string_view> {
    return {BN_bn2dec(this->as_ptr())};
  }
}
