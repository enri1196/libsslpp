module;

#include <memory>
#include <openssl/ossl_typ.h>
#include <stdexcept>
#include <string_view>

#include <openssl/asn1.h>

using namespace std;

export module asn1:octet_string;

namespace openssl::asn1 {

static void ao_own_free(ASN1_OCTET_STRING *x) { ASN1_OCTET_STRING_free(x); }
static void ao_ref_free(ASN1_OCTET_STRING *x) {}

export class Asn1OctetString {
private:
  shared_ptr<ASN1_OCTET_STRING> m_ssl_type;

  Asn1OctetString() : m_ssl_type(ASN1_OCTET_STRING_new(), &ao_own_free) {}
  Asn1OctetString(ASN1_OCTET_STRING *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &ao_own_free : &ao_ref_free) {}

public:
  static auto own(ASN1_OCTET_STRING *ref) -> Asn1OctetString {
    return Asn1OctetString(ref);
  }
  static auto ref(ASN1_OCTET_STRING *ref) -> Asn1OctetString {
    return Asn1OctetString(ref, false);
  }

  static auto from(string_view &&data) -> Asn1OctetString {
    auto octet_string = ASN1_OCTET_STRING_new();
    if (ASN1_OCTET_STRING_set(
        octet_string,
        reinterpret_cast<const unsigned char*>(data.data()),
        static_cast<int>(data.length())
      ) <= 0) {
      throw runtime_error("OctetString conversion from string Error");
    }
    return {Asn1OctetString(octet_string)};
  }

  auto as_ptr() const noexcept -> ASN1_OCTET_STRING* { return m_ssl_type.get(); }
};

}
