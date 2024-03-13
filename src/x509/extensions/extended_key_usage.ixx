module;

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/x509v3.h>

export module x509:eku_ext;

namespace openssl::x509 {

export class ExtendedKeyUsage {
public:
  enum class EExtendedKeyUsage : std::uint32_t {
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

  static auto from(std::uint32_t value) -> ExtendedKeyUsage {
    auto eku = ExtendedKeyUsage();
    eku.value = value;
    return eku;
  }

  auto to_string() const -> std::string {
    std::string str;
    if (value & XKU_SSL_SERVER) str += "SSL_SERVER, ";
    if (value & XKU_SSL_CLIENT) str += "SSL_CLIENT, ";
    if (value & XKU_SMIME) str += "SMIME, ";
    if (value & XKU_CODE_SIGN) str += "CODE_SIGN, ";
    if (value & XKU_OCSP_SIGN) str += "OCSP_SIGN, ";
    if (value & XKU_TIMESTAMP) str += "TIMESTAMP, ";
    if (value & XKU_DVCS) str += "DVCS, ";
    if (value & XKU_ANYEKU) str += "ANYEKU, ";
    if (value == UINT32_MAX) str += "ABSENT, ";

    // Remove the trailing comma and space
    if (!str.empty()) str.resize(str.size() - 2);

    return str;
  }

  auto to_vec() const -> std::vector<EExtendedKeyUsage> {
    std::vector<EExtendedKeyUsage> vec;
    if (value & XKU_SSL_SERVER) vec.push_back(EExtendedKeyUsage::SSL_SERVER);
    if (value & XKU_SSL_CLIENT) vec.push_back(EExtendedKeyUsage::SSL_CLIENT);
    if (value & XKU_SMIME) vec.push_back(EExtendedKeyUsage::SMIME);
    if (value & XKU_CODE_SIGN) vec.push_back(EExtendedKeyUsage::CODE_SIGN);
    if (value & XKU_OCSP_SIGN) vec.push_back(EExtendedKeyUsage::OCSP_SIGN);
    if (value & XKU_TIMESTAMP) vec.push_back(EExtendedKeyUsage::TIMESTAMP);
    if (value & XKU_DVCS) vec.push_back(EExtendedKeyUsage::DVCS);
    if (value & XKU_ANYEKU) vec.push_back(EExtendedKeyUsage::ANYEKU);
    if (value == UINT32_MAX) vec.push_back(EExtendedKeyUsage::ABSENT);
    return vec;
  }

private:
  std::int32_t value;
};


}