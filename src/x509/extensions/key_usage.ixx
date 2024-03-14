module;

#include <cstdint>
#include <string>
#include <vector>
#include <span>

#include <openssl/x509v3.h>

using namespace std;

export module x509:ku_ext;

import :x509_ext;

namespace openssl::x509 {

export class KeyUsage {
public:
  enum class EKeyUsage : uint32_t {
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

  static auto from(uint32_t value) -> KeyUsage {
    auto ku = KeyUsage();
    ku.value = value;
    return ku;
  }

  static auto from(span<EKeyUsage> &&value) -> KeyUsage {
    auto ku = KeyUsage();
    for (auto val : value) {
      ku.value |= static_cast<int32_t>(val);
    }
    return ku;
  }

  auto to_string() const -> string {
    string str;
    if (value & KU_DIGITAL_SIGNATURE) str += "DIGITAL_SIGNATURE, ";
    if (value & KU_NON_REPUDIATION) str += "NON_REPUDIATION, ";
    if (value & KU_KEY_ENCIPHERMENT) str += "KEY_ENCIPHERMENT, ";
    if (value & KU_DATA_ENCIPHERMENT) str += "DATA_ENCIPHERMENT, ";
    if (value & KU_KEY_AGREEMENT) str += "KEY_AGREEMENT, ";
    if (value & KU_KEY_CERT_SIGN) str += "KEY_CERT_SIGN, ";
    if (value & KU_CRL_SIGN) str += "CRL_SIGN, ";
    if (value & KU_ENCIPHER_ONLY) str += "ENCIPHER_ONLY, ";
    if (value & KU_DECIPHER_ONLY) str += "DECIPHER_ONLY, ";
    if (value & UINT32_MAX) str += "ABSENT, ";

    // Remove the trailing comma and space
    if (!str.empty()) str.resize(str.size() - 2);

    return str;
  }

  auto to_vec() const -> vector<EKeyUsage> {
    vector<EKeyUsage> vec;
    if (value & KU_DIGITAL_SIGNATURE) vec.push_back(EKeyUsage::DIGITAL_SIGNATURE);
    if (value & KU_NON_REPUDIATION) vec.push_back(EKeyUsage::NON_REPUDIATION);
    if (value & KU_KEY_ENCIPHERMENT) vec.push_back(EKeyUsage::KEY_ENCIPHERMENT);
    if (value & KU_DATA_ENCIPHERMENT) vec.push_back(EKeyUsage::DATA_ENCIPHERMENT);
    if (value & KU_KEY_AGREEMENT) vec.push_back(EKeyUsage::KEY_AGREEMENT);
    if (value & KU_KEY_CERT_SIGN) vec.push_back(EKeyUsage::KEY_CERT_SIGN);
    if (value & KU_CRL_SIGN) vec.push_back(EKeyUsage::CRL_SIGN);
    if (value & KU_ENCIPHER_ONLY) vec.push_back(EKeyUsage::ENCIPHER_ONLY);
    if (value & KU_DECIPHER_ONLY) vec.push_back(EKeyUsage::DECIPHER_ONLY);
    if (value & UINT32_MAX) vec.push_back(EKeyUsage::ABSENT);
    return vec;
  }

private:
  uint32_t value;
};


}