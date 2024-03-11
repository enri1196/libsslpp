module;

#include <cstdint>
#include <optional>
#include <string_view>

#include <openssl/x509v3.h>

export module x509:eku_ext;

namespace openssl::x509 {

export class ExtendedKeyUsage {
public:
  enum EExtendedKeyUsage : std::uint32_t {
    SSL_SERVER  = XKU_SSL_SERVER,
    SSL_CLIENT  = XKU_SSL_CLIENT,
    SMIME       = XKU_SMIME,
    CODE_SIGN   = XKU_CODE_SIGN,
    OCSP_SIGN   = XKU_OCSP_SIGN,
    TIMESTAMP   = XKU_TIMESTAMP,
    DVCS        = XKU_DVCS,
    ANYEKU      = XKU_ANYEKU,
    ABSENT      = UINT32_MAX
  };

  static auto from(std::uint32_t value) -> std::optional<ExtendedKeyUsage> {
    auto eku = ExtendedKeyUsage();
    switch (value) {
      case SSL_SERVER:
        eku.value = SSL_SERVER;
      case SSL_CLIENT:
        eku.value = SSL_CLIENT;
      case SMIME:
        eku.value = SMIME;
      case CODE_SIGN:
        eku.value = CODE_SIGN;
      case OCSP_SIGN:
        eku.value = OCSP_SIGN;
      case TIMESTAMP:
        eku.value = TIMESTAMP;
      case DVCS:
        eku.value = DVCS;
      case ANYEKU:
        eku.value = ANYEKU;
      case ABSENT:
        eku.value = ABSENT;
      default:
        return std::nullopt;
    }
    return eku;
  }

  constexpr operator EExtendedKeyUsage() const { return value; }

  auto to_string() const -> std::string_view {
    std::string_view str;
    switch (value) {
      case SSL_SERVER:
        str = "SSL_SERVER";
      case SSL_CLIENT:
        str = "SSL_CLIENT";
      case SMIME:
        str = "SMIME";
      case CODE_SIGN:
        str = "CODE_SIGN";
      case OCSP_SIGN:
        str = "OCSP_SIGN";
      case TIMESTAMP:
        str = "TIMESTAMP";
      case DVCS:
        str = "DVCS";
      case ANYEKU:
        str = "ANYEKU";
      case ABSENT:
        str = "ABSENT";
    }
    return str;
  }

private:
  EExtendedKeyUsage value;
};


}