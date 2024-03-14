module;

#include <ctime>
#include <chrono>
#include <memory>
#include <string_view>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

using namespace std;

export module asn1:time;

import bio;

namespace openssl::asn1 {

static void at_own_free(ASN1_TIME *x) { ASN1_TIME_free(x); }
static void at_ref_free(ASN1_TIME *) {}

export class Asn1Time {
private:
  shared_ptr<ASN1_TIME> m_ssl_type;

  Asn1Time() = delete;
  Asn1Time(ASN1_TIME *time, bool take_ownership = true)
      : m_ssl_type(time, take_ownership ? &at_own_free : &at_ref_free) {}

public:
  static auto own(ASN1_TIME *ref) -> Asn1Time {
    return Asn1Time(ref, false);
  }
  static auto ref(ASN1_TIME *ref) -> Asn1Time {
    return Asn1Time(ref, false);
  }

  static auto now() -> Asn1Time {
    auto t = ASN1_TIME_new();
    time_t current_time = time(nullptr);
    ASN1_TIME_set(t, current_time);
    return Asn1Time::own(t);
  }

  static auto from(const string_view &&time) -> Asn1Time {
    auto asn1 = ASN1_TIME_new();
    if (ASN1_TIME_set_string(asn1, time.data()) <= 0) {
      throw runtime_error("Asn1Time conversion from string Error");
    }
    return Asn1Time(asn1);
  }

  auto as_ptr() const noexcept -> ASN1_TIME * { return m_ssl_type.get(); }

  auto to_string() const -> string {
    auto bio = bio::SSLBio::memory();
    if (ASN1_TIME_print(bio.as_ptr(), this->as_ptr()) != 1) {
      throw runtime_error("Asn1Time to string Error");
    }
    return bio.get_mem_ptr();
  }

  auto to_time_point() const -> chrono::system_clock::time_point {
    struct tm tm;
    if (ASN1_TIME_to_tm(this->as_ptr(), &tm) != 1) {
      throw runtime_error("Asn1Time to Chrono Error");
    }
    return chrono::system_clock::from_time_t(mktime(&tm));
  }
}; // class Asn1Time

} // namespace openssl::asn1
