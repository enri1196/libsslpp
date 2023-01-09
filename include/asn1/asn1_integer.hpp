#pragma once

#include <cstddef>
#include <ctime>
#include <memory>
#include <chrono>
#include <string_view>

#include <openssl/asn1.h>

#include "bio.hpp"
#include "big_num.hpp"
#include "internal/ssl_interface.hpp"
#include "openssl/ossl_typ.h"

namespace openssl {

class Asn1Integer {
private:
  struct SSLDeleter {
    auto operator()(ASN1_INTEGER* ptr) { ASN1_INTEGER_free(ptr); }
  };
  using SSLPtr = std::unique_ptr<ASN1_INTEGER, SSLDeleter>;
  SSLPtr m_ssl_type;

  Asn1Integer() : m_ssl_type(ASN1_INTEGER_new()) {}

public:
  Asn1Integer(Asn1Integer &&) noexcept = default;
  Asn1Integer(const Asn1Integer &) = delete;
  auto operator=(Asn1Integer &&) noexcept -> Asn1Integer & = default;
  auto operator=(const Asn1Integer &) -> Asn1Integer & = delete;
  explicit Asn1Integer(ASN1_INTEGER *ptr) : m_ssl_type(ptr) {}
  ~Asn1Integer() = default;

  auto as_ptr() const noexcept -> ASN1_INTEGER* { return m_ssl_type.get(); }

  static auto from(const BigNum&& bni) -> Expected<Asn1Integer> {
    auto asn_int = BN_to_ASN1_INTEGER(bni.as_ptr(), nullptr);
    if (asn_int == nullptr) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return {Asn1Integer(asn_int)};
  }

  auto to_string() const -> Expected<std::string_view> {
    auto bn = TRY(BigNum::from(std::move(*this)));
    return bn.to_string();
  }
};

}  // namespace openssl
