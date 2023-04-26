#pragma once

#include <openssl/asn1.h>

#include "bio.hpp"
#include "internal/ssl_interface.hpp"

namespace openssl {

class Asn1OctetString {
private:
  using SSLPtr = std::shared_ptr<ASN1_OCTET_STRING>;
  SSLPtr m_ssl_type;

  Asn1OctetString() : m_ssl_type(ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free) {}

public:
  Asn1OctetString(Asn1OctetString &&) noexcept = default;
  Asn1OctetString(const Asn1OctetString &) = delete;
  auto operator=(Asn1OctetString &&) noexcept -> Asn1OctetString & = default;
  auto operator=(const Asn1OctetString &) -> Asn1OctetString & = default;
  explicit Asn1OctetString(ASN1_OCTET_STRING *ptr,
                      std::function<void(ASN1_OCTET_STRING *)> free_fn = ASN1_OCTET_STRING_free)
      : m_ssl_type(ptr, free_fn) {}
  ~Asn1OctetString() = default;

  auto as_ptr() const noexcept -> ASN1_OCTET_STRING* { return m_ssl_type.get(); }

  static auto from(const std::string_view&& data) -> Expected<Asn1OctetString> {
    auto octet_string = ASN1_OCTET_STRING_new();
    if (ASN1_OCTET_STRING_set(
        octet_string,
        reinterpret_cast<const unsigned char*>(data.data()),
        static_cast<int>(data.length())
      ) <= 0) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return {Asn1OctetString(octet_string)};
  }
};

}
