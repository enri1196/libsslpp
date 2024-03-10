#pragma once

#include <memory>
#include <openssl/ossl_typ.h>
#include <string_view>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "../bio.hpp"

namespace openssl::asn1 {

static void at_own_free(ASN1_TIME *x) { ASN1_TIME_free(x); }
static void at_ref_free(ASN1_TIME *x) {}

class Asn1Time {
private:
  std::shared_ptr<ASN1_TIME> m_ssl_type;

  Asn1Time() : m_ssl_type(ASN1_TIME_new(), &at_own_free) {}
  Asn1Time(ASN1_TIME *time, bool take_ownership = true)
      : m_ssl_type(time, take_ownership ? &at_own_free : &at_ref_free) {}

public:
  static auto ref(ASN1_TIME *ref) -> Asn1Time {
    return Asn1Time(ref, false);
  }

  static auto from(const std::string_view &&time) -> Asn1Time {
    auto asn1 = ASN1_TIME_new();
    if (ASN1_TIME_set_string(asn1, time.data()) <= 0) {
      throw std::runtime_error("Asn1Time conversion from string Error");
    }
    return Asn1Time(asn1);
  }

  auto as_ptr() const noexcept -> ASN1_TIME * { return m_ssl_type.get(); }

  auto to_string() const -> std::string {
    auto bio = openssl::bio::SSLBio::memory();
    if (ASN1_TIME_print(bio.as_ptr(), this->as_ptr()) != 1) {
      throw std::runtime_error("Asn1Time to string Error");
    }
    return bio.get_mem_ptr();
  }

  auto to_time_point() const -> std::chrono::system_clock::time_point {
    struct tm tm;
    if (ASN1_TIME_to_tm(this->as_ptr(), &tm) != 1) {
      throw std::runtime_error("Asn1Time to Chrono Error");
    }
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
  }
}; // class Asn1Time

} // namespace openssl
