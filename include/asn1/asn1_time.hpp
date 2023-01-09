#pragma once

#include <ctime>
#include <memory>
#include <chrono>
#include <string_view>

#include <openssl/asn1.h>

#include "bio.hpp"
#include "internal/ssl_interface.hpp"
#include "openssl/bio.h"
#include "openssl/buffer.h"

namespace openssl {

class Asn1Time {
private:
  struct SSLDeleter {
    auto operator()(ASN1_TIME* ptr) { ASN1_TIME_free(ptr); }
  };
  using SSLPtr = std::unique_ptr<ASN1_TIME, SSLDeleter>;
  SSLPtr m_ssl_type;

  Asn1Time() : m_ssl_type(ASN1_TIME_new()) {}

public:
  Asn1Time(Asn1Time &&) noexcept = default;
  Asn1Time(const Asn1Time &) = delete;
  auto operator=(Asn1Time &&) noexcept -> Asn1Time & = default;
  auto operator=(const Asn1Time &) -> Asn1Time & = delete;
  explicit Asn1Time(ASN1_TIME *ptr) : m_ssl_type(ptr) {}
  ~Asn1Time() = default;

  auto as_ptr() const noexcept -> ASN1_TIME* { return m_ssl_type.get(); }

  auto to_string() const -> Expected<std::string_view> {
    auto bio = SSLBio::init();
    if (ASN1_TIME_print(bio.as_ptr(), this->as_ptr()) != 1) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return bio.get_mem_ptr();
  }

  auto to_time_point() const -> Expected<std::chrono::system_clock::time_point> {
    struct tm tm;
    if (ASN1_TIME_to_tm(this->as_ptr(), &tm) != 1) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
  }
};  // class Asn1Time

}  // namespace openssl
