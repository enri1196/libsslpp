#include "asn1/asn1_integer.hpp"
#include "openssl/ossl_typ.h"
#include <memory>

namespace openssl {
Asn1Integer::Asn1Integer() : m_ssl_type(ASN1_INTEGER_new(), ASN1_INTEGER_free) {}
Asn1Integer::Asn1Integer(Asn1Integer &&) noexcept = default;
Asn1Integer::Asn1Integer(const Asn1Integer &) = default;
auto Asn1Integer::operator=(Asn1Integer &&) noexcept -> Asn1Integer & = default;
auto Asn1Integer::operator=(const Asn1Integer &) -> Asn1Integer & = default;
Asn1Integer::Asn1Integer(ASN1_INTEGER *ptr,
                         std::function<void(ASN1_INTEGER *)> free_fn)
    : m_ssl_type(ptr, free_fn) {}
Asn1Integer::~Asn1Integer() = default;

auto Asn1Integer::as_ptr() const noexcept -> ASN1_INTEGER * {
  return m_ssl_type.get();
}

auto Asn1Integer::clone() const -> Asn1Integer {
  return Asn1Integer(ASN1_INTEGER_dup(this->as_ptr()));
}

auto Asn1Integer::from(const BigNum &&bni) -> Expected<Asn1Integer> {
  auto asn1_int = BN_to_ASN1_INTEGER(bni.as_ptr(), nullptr);
  if (asn1_int == nullptr) {
    return Unexpected(SSLError(ErrorCode::ConversionError));
  }
  return {Asn1Integer(asn1_int)};
}

// std::uint64_t r = 3'125'621'985'792'713'081;
auto Asn1Integer::from(const std::int64_t new_int) -> Expected<Asn1Integer> {
  auto asn_int = Asn1Integer();
  if (ASN1_INTEGER_set_int64(asn_int.as_ptr(), new_int) <= 0) {
    return Unexpected(SSLError(ErrorCode::ConversionError));
  }
  return {std::move(asn_int)};
}

auto Asn1Integer::from(const std::uint64_t new_int) -> Expected<Asn1Integer> {
  auto asn_int = Asn1Integer();
  if (ASN1_INTEGER_set_uint64(asn_int.as_ptr(), new_int) <= 0) {
    return Unexpected(SSLError(ErrorCode::ConversionError));
  }
  return {std::move(asn_int)};
}

auto Asn1Integer::to_string() const -> Expected<std::string_view> {
  auto bn = TRY(BigNum::from(std::move(*this)));
  return bn.to_string();
}

auto Asn1Integer::to_der() -> Expected<std::vector<std::uint8_t>> {
  unsigned char *asn1_der_data{};
  auto size = i2d_ASN1_INTEGER(this->as_ptr(), &asn1_der_data);
  if (size < 0) {
    return Unexpected(SSLError(ErrorCode::ConversionError));
  }
  std::vector<std::uint8_t> asn1_der{};
  asn1_der.resize(static_cast<std::size_t>(size));
  memmove(asn1_der.data(), asn1_der_data, static_cast<std::size_t>(size));
  return {asn1_der};
}

} // namespace openssl
