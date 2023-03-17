#pragma once

#include <openssl/asn1.h>

#include "bio.hpp"
#include "big_num.hpp"
#include "internal/ssl_interface.hpp"

namespace openssl {

class BigNum;

class Asn1Integer {
private:
  using SSLPtr = std::shared_ptr<ASN1_INTEGER>;
  SSLPtr m_ssl_type;

  Asn1Integer() : m_ssl_type(ASN1_INTEGER_new(), ASN1_INTEGER_free) {}

public:
  Asn1Integer(Asn1Integer &&) noexcept;
  Asn1Integer(const Asn1Integer &);
  auto operator=(Asn1Integer &&) noexcept -> Asn1Integer &;
  auto operator=(const Asn1Integer &) -> Asn1Integer &;
  explicit Asn1Integer(ASN1_INTEGER *ptr,
                      std::function<void(ASN1_INTEGER *)> free_fn = ASN1_INTEGER_free);
  ~Asn1Integer();

  auto as_ptr() const noexcept -> ASN1_INTEGER*;

  static auto from(const BigNum&& bni) -> Expected<Asn1Integer>;

  // std::uint64_t r = 3'125'621'985'792'713'081;
  static auto from(const std::int64_t new_int) -> Expected<Asn1Integer>;

  static auto from(const std::uint64_t new_int) -> Expected<Asn1Integer>;

  auto to_string() const -> Expected<std::string_view>;

  auto to_der() -> Expected<std::vector<std::uint8_t>>;
};

}  // namespace openssl
