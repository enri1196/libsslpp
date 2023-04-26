#pragma once

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "bio.hpp"

namespace openssl {

class Asn1Time {
private:
  using SSLPtr = std::shared_ptr<ASN1_TIME>;
  SSLPtr m_ssl_type;

  Asn1Time() : m_ssl_type(ASN1_TIME_new(), ASN1_TIME_free) {}

public:
  Asn1Time(Asn1Time &&) noexcept = default;
  Asn1Time(const Asn1Time &) = delete;
  auto operator=(Asn1Time &&) noexcept -> Asn1Time & = default;
  auto operator=(const Asn1Time &) -> Asn1Time & = delete;
  explicit Asn1Time(
      ASN1_TIME *ptr,
      std::function<void(ASN1_TIME *)> free_fn = ASN1_TIME_free)
      : m_ssl_type(ptr, free_fn) {}
  ~Asn1Time() = default;

  auto as_ptr() const noexcept -> ASN1_TIME * { return m_ssl_type.get(); }

  static auto from(const std::string_view &&time) -> Expected<Asn1Time> {
    auto asn1 = ASN1_TIME_new();
    if (ASN1_TIME_set_string(asn1, time.data()) <= 0) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return {Asn1Time(asn1)};
  }

  auto to_string() const -> Expected<std::string_view> {
    auto bio = SSLBio::init();
    if (ASN1_TIME_print(bio.as_ptr(), this->as_ptr()) != 1) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return bio.get_mem_ptr();
  }

  auto to_time_point() const
      -> Expected<std::chrono::system_clock::time_point> {
    struct tm tm;
    if (ASN1_TIME_to_tm(this->as_ptr(), &tm) != 1) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
  }
}; // class Asn1Time

} // namespace openssl
