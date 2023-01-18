#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <chrono>
#include <string_view>

#include <openssl/asn1.h>

#include "bio.hpp"
#include "big_num.hpp"
#include "internal/ssl_interface.hpp"

namespace openssl {

class Asn1Integer {
private:
  using SSLPtr = std::shared_ptr<ASN1_INTEGER>;
  SSLPtr m_ssl_type;

  Asn1Integer() : m_ssl_type(ASN1_INTEGER_new(), ASN1_INTEGER_free) {}

public:
  Asn1Integer(Asn1Integer &&) noexcept = default;
  Asn1Integer(const Asn1Integer &) = default;
  auto operator=(Asn1Integer &&) noexcept -> Asn1Integer & = default;
  auto operator=(const Asn1Integer &) -> Asn1Integer & = default;
  explicit Asn1Integer(ASN1_INTEGER *ptr,
                      std::function<void(ASN1_INTEGER *)> free_fn = ASN1_INTEGER_free)
      : m_ssl_type(ptr, free_fn) {}
  ~Asn1Integer() = default;

  auto as_ptr() const noexcept -> ASN1_INTEGER* { return m_ssl_type.get(); }

  static auto from(const BigNum&& bni) -> Expected<Asn1Integer> {
    auto asn_int = BN_to_ASN1_INTEGER(bni.as_ptr(), nullptr);
    if (asn_int == nullptr) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return {Asn1Integer(asn_int)};
  }

  // std::uint64_t r = 3'125'621'985'792'713'081;
  static auto from(const std::int64_t new_int) -> Expected<Asn1Integer> {
    auto asn_int = Asn1Integer();
    if (ASN1_INTEGER_set_int64(asn_int.as_ptr(), new_int) <= 0) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return {std::move(asn_int)};
  }

  static auto from(const std::uint64_t new_int) -> Expected<Asn1Integer> {
    auto asn_int = Asn1Integer();
    if (ASN1_INTEGER_set_uint64(asn_int.as_ptr(), new_int) <= 0) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return {std::move(asn_int)};
  }

  auto to_string() const -> Expected<std::string_view> {
    auto bn = TRY(BigNum::from(std::move(*this)));
    return bn.to_string();
  }
};

}  // namespace openssl
