module;

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <stdexcept>

#include <openssl/x509v3.h>

using namespace std;

export module x509:eku_ext;

import :x509_ext;

namespace openssl::x509 {

export class ExtendedKeyUsage {
public:
  enum class EExtendedKeyUsage : uint32_t {
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

  static auto from(uint32_t value) -> ExtendedKeyUsage {
    auto eku = ExtendedKeyUsage();
    eku.value = value;
    return eku;
  }

  static auto from(span<EExtendedKeyUsage> &&value) -> ExtendedKeyUsage {
    auto ku = ExtendedKeyUsage();
    for (auto val : value) {
      ku.value |= static_cast<uint32_t>(val);
    }
    return ku;
  }

  auto to_string() const -> string {
    string str;
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

  auto to_vec() const -> vector<EExtendedKeyUsage> {
    vector<EExtendedKeyUsage> vec;
    if (value & XKU_SSL_SERVER)   vec.push_back(EExtendedKeyUsage::SSL_SERVER);
    if (value & XKU_SSL_CLIENT)   vec.push_back(EExtendedKeyUsage::SSL_CLIENT);
    if (value & XKU_SMIME)        vec.push_back(EExtendedKeyUsage::SMIME);
    if (value & XKU_CODE_SIGN)    vec.push_back(EExtendedKeyUsage::CODE_SIGN);
    if (value & XKU_OCSP_SIGN)    vec.push_back(EExtendedKeyUsage::OCSP_SIGN);
    if (value & XKU_TIMESTAMP)    vec.push_back(EExtendedKeyUsage::TIMESTAMP);
    if (value & XKU_DVCS)         vec.push_back(EExtendedKeyUsage::DVCS);
    if (value & XKU_ANYEKU)       vec.push_back(EExtendedKeyUsage::ANYEKU);
    if (value == UINT32_MAX)      vec.push_back(EExtendedKeyUsage::ABSENT);
    return vec;
  }

  auto to_x509_ext() -> X509Extension {
    X509V3_CTX ctx;
    int nid = static_cast<int>(X509V3ExtensionNid::EXT_KEY_USAGE);
    X509V3_set_ctx(&ctx, nullptr, nullptr, nullptr, nullptr, 0);

    auto data = this->to_string();
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, data.c_str());

    if (ext == nullptr) {
      throw runtime_error("Error creating ext_key_usage extension");
    }
    return X509Extension::own(ext);
  }

private:
  uint32_t value;
};

}
