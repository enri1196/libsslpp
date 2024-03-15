module;

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <stdexcept>
#include <print>

#include <openssl/x509v3.h>

using namespace std;

export module x509:ku_ext;

import :x509_ext;

namespace openssl::x509 {

export enum class EKeyUsage : uint32_t {
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

export class KeyUsage {
public:
  static auto from(uint32_t value) -> KeyUsage {
    auto ku = KeyUsage();
    ku.value = value;
    return ku;
  }

  static auto from(vector<EKeyUsage> &&value) -> KeyUsage {
    auto ku = KeyUsage();
    for (auto val : value) {
      ku.value |= static_cast<uint32_t>(val);
    }
    return ku;
  }

  auto to_string() const -> string {
    string str;

    if (value == UINT32_MAX) {
      str += "ABSENT";
    } else {
      if (value & KU_DIGITAL_SIGNATURE) str += "digitalSignature,";
      if (value & KU_NON_REPUDIATION) str += "nonRepudiation,";
      if (value & KU_KEY_ENCIPHERMENT) str += "keyEncipherment,";
      if (value & KU_DATA_ENCIPHERMENT) str += "dataEncipherment,";
      if (value & KU_KEY_AGREEMENT) str += "keyAgreement,";
      if (value & KU_KEY_CERT_SIGN) str += "keyCertSign,";
      if (value & KU_CRL_SIGN) str += "cRLSign,";
      if (value & KU_ENCIPHER_ONLY) str += "encipherOnly,";
      if (value & KU_DECIPHER_ONLY) str += "decipherOnly,";
      if (!str.empty()) {
        str.resize(str.size() - 1);
      }
    }

    return str;
  }

  auto to_vec() const -> vector<EKeyUsage> {
    vector<EKeyUsage> vec;
    if (value & KU_DIGITAL_SIGNATURE)   vec.push_back(EKeyUsage::DIGITAL_SIGNATURE);
    if (value & KU_NON_REPUDIATION)     vec.push_back(EKeyUsage::NON_REPUDIATION);
    if (value & KU_KEY_ENCIPHERMENT)    vec.push_back(EKeyUsage::KEY_ENCIPHERMENT);
    if (value & KU_DATA_ENCIPHERMENT)   vec.push_back(EKeyUsage::DATA_ENCIPHERMENT);
    if (value & KU_KEY_AGREEMENT)       vec.push_back(EKeyUsage::KEY_AGREEMENT);
    if (value & KU_KEY_CERT_SIGN)       vec.push_back(EKeyUsage::KEY_CERT_SIGN);
    if (value & KU_CRL_SIGN)            vec.push_back(EKeyUsage::CRL_SIGN);
    if (value & KU_ENCIPHER_ONLY)       vec.push_back(EKeyUsage::ENCIPHER_ONLY);
    if (value & KU_DECIPHER_ONLY)       vec.push_back(EKeyUsage::DECIPHER_ONLY);
    if (value & UINT32_MAX)             vec.push_back(EKeyUsage::ABSENT);
    return vec;
  }

  auto to_x509_ext() -> X509Extension {
    X509V3_CTX ctx;
    int nid = static_cast<int>(X509V3ExtensionNid::KEY_USAGE);
    X509V3_set_ctx(&ctx, nullptr, nullptr, nullptr, nullptr, 0);

    auto data = this->to_string();
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, data.c_str());

    if (ext == nullptr) {
      throw runtime_error("Error creating key_usage extension");
    }
    return X509Extension::own(ext);
  }

private:
  uint32_t value;
};

}