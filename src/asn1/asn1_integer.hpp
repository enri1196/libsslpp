#pragma once

#include <cstring>
#include <memory>
#include <openssl/bn.h>
#include <stdexcept>
#include <vector>
#include <string>

#include <openssl/asn1.h>

// #include "../bio.hpp"
#include "../bignum.hpp"

namespace openssl::asn1 {

static void ai_own_free(ASN1_INTEGER *x) { ASN1_INTEGER_free(x); }
static void ai_ref_free(ASN1_INTEGER *x) {}

class BigNum;

class Asn1Integer {
private:
  std::shared_ptr<ASN1_INTEGER> m_ssl_type;

  Asn1Integer() : m_ssl_type(ASN1_INTEGER_new(), &ai_own_free) {}
  Asn1Integer(ASN1_INTEGER *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &ai_own_free : &ai_ref_free) {}

public:
  static auto ref(ASN1_INTEGER *ref) -> Asn1Integer {
    return Asn1Integer(ref, false);
  }

  // std::uint64_t r = 3'125'621'985'792'713'081;
  static auto from(const std::int64_t new_int) -> Asn1Integer {
    auto asn_int = Asn1Integer();
    if (ASN1_INTEGER_set_int64(asn_int.as_ptr(), new_int) <= 0) {
      throw std::runtime_error("Asn1Integer conversion from i64 Error");
    }
    return asn_int;
  }

  static auto from(const std::uint64_t new_int) -> Asn1Integer {
    auto asn_int = Asn1Integer();
    if (ASN1_INTEGER_set_uint64(asn_int.as_ptr(), new_int) <= 0) {
      throw std::runtime_error("Asn1Integer conversion from u64 Error");
    }
    return asn_int;
  }

  static auto from(bn::BigNum&& bni) -> Asn1Integer {
    auto asn1_int = BN_to_ASN1_INTEGER(bni.as_ptr(), nullptr);
    if (asn1_int == nullptr) {
      throw std::runtime_error("Asn1Integer conversion from BN Error");
    }
    return Asn1Integer(asn1_int);
  }

  auto as_ptr() const noexcept -> ASN1_INTEGER* {
    return m_ssl_type.get();
  }

  auto to_string() const -> std::string {
    auto bn = BN_new();
    ASN1_INTEGER_to_BN(this->as_ptr(), bn);
    return BN_bn2dec(bn);
  }

  auto to_bytes() -> std::vector<std::uint8_t> {
    unsigned char *asn1_der_data{};
    auto size = i2d_ASN1_INTEGER(this->as_ptr(), &asn1_der_data);
    if (size < 0) {
      throw std::runtime_error("Asn1Integer to bytes Error");
    }
    std::vector<std::uint8_t> asn1_der{};
    asn1_der.resize(static_cast<std::size_t>(size));
    std::memmove(asn1_der.data(), asn1_der_data, static_cast<std::size_t>(size));
    return asn1_der;
  }
};

}  // namespace openssl
