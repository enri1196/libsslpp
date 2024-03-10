#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include <openssl/x509v3.h>

namespace openssl::x509 {

class KeyUsage {
public:
  enum EKeyUsage : std::uint32_t {
    DIGITAL_SIGNATURE   = KU_DIGITAL_SIGNATURE,
    NON_REPUDIATION     = KU_NON_REPUDIATION,
    KEY_ENCIPHERMENT    = KU_KEY_ENCIPHERMENT,
    DATA_ENCIPHERMENT   = KU_DATA_ENCIPHERMENT,
    KEY_AGREEMENT       = KU_KEY_AGREEMENT,
    KEY_CERT_SIGN       = KU_KEY_CERT_SIGN,
    CRL_SIGN            = KU_CRL_SIGN,
    ENCIPHER_ONLY       = KU_ENCIPHER_ONLY,
    DECIPHER_ONLY       = KU_DECIPHER_ONLY,
    ABSENT              = UINT32_MAX
  };

  static auto from(std::uint32_t value) -> std::optional<KeyUsage> {
    auto ku = KeyUsage();
    switch (value) {
      case DIGITAL_SIGNATURE:
        ku.value = DIGITAL_SIGNATURE;
      case NON_REPUDIATION:
        ku.value = NON_REPUDIATION;
      case KEY_ENCIPHERMENT:
        ku.value = KEY_ENCIPHERMENT;
      case DATA_ENCIPHERMENT:
        ku.value = DATA_ENCIPHERMENT;
      case KEY_AGREEMENT:
        ku.value = KEY_AGREEMENT;
      case KEY_CERT_SIGN:
        ku.value = KEY_CERT_SIGN;
      case CRL_SIGN:
        ku.value = CRL_SIGN;
      case ENCIPHER_ONLY:
        ku.value = ENCIPHER_ONLY;
      case DECIPHER_ONLY:
        ku.value = DECIPHER_ONLY;
      case ABSENT:
        ku.value = ABSENT;
      default:
        return std::nullopt;
    }
    return ku;
  }

  constexpr operator EKeyUsage() const { return value; }

  auto to_string() const -> std::string_view {
    std::string_view ku_s;
    switch (value) {
      case DIGITAL_SIGNATURE:
        ku_s = "DIGITAL_SIGNATURE";
      case NON_REPUDIATION:
        ku_s = "NON_REPUDIATION";
      case KEY_ENCIPHERMENT:
        ku_s = "KEY_ENCIPHERMENT";
      case DATA_ENCIPHERMENT:
        ku_s = "DATA_ENCIPHERMENT";
      case KEY_AGREEMENT:
        ku_s = "KEY_AGREEMENT";
      case KEY_CERT_SIGN:
        ku_s = "KEY_CERT_SIGN";
      case CRL_SIGN:
        ku_s = "CRL_SIGN";
      case ENCIPHER_ONLY:
        ku_s = "ENCIPHER_ONLY";
      case DECIPHER_ONLY:
        ku_s = "DECIPHER_ONLY";
      case ABSENT:
        ku_s = "ABSENT";
    }
    return ku_s;
  }

private:
  EKeyUsage value;
};


}