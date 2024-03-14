module;

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

using namespace std;

export module x509:x509_cert;

import bn;
import asn1;
import bio;
import evp;
import :x509_name;
import :x509_req;
import :x509_ext;
import :ku_ext;
import :eku_ext;

namespace openssl::x509 {

static void x509_own_free(X509 *x) { X509_free(x); }
static void x509_ref_free(X509 *x) {}

export class X509Certificate {
private:
  shared_ptr<X509> m_ssl_type;

  X509Certificate() = delete;
  explicit X509Certificate(X509 *cert, bool take_ownership = true)
      : m_ssl_type(cert, take_ownership ? &x509_own_free : &x509_ref_free) {}

public:
  static auto own(X509 *ref) -> X509Certificate { return X509Certificate(ref); }
  static auto ref(X509 *ref) -> X509Certificate {
    return X509Certificate(ref, false);
  }

  static auto from(bio::SSLBio &&bio_cert) -> X509Certificate {
    auto cert = PEM_read_bio_X509(bio_cert.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      throw runtime_error("Cert conversion Error");
    }
    return X509Certificate(cert);
  }

  static auto from(string_view &&cert_str) -> X509Certificate {
    auto bio_str = bio::SSLBio::memory();
    bio_str.write_mem(std::move(cert_str));
    auto *cert = PEM_read_bio_X509(bio_str.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      throw runtime_error("Cert conversion Error");
    }
    return X509Certificate(cert);
  }

  static auto from(span<uint8_t> &&cert_bytes) -> X509Certificate {
    auto bio_bytes = bio::SSLBio::memory();
    bio_bytes.write_mem(std::move(cert_bytes));
    auto *cert =
        PEM_read_bio_X509(bio_bytes.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      throw runtime_error("Cert conversion Error");
    }
    return X509Certificate(cert);
  }

  auto as_ptr() const noexcept -> X509 * { return m_ssl_type.get(); }

  auto serial() const -> asn1::Asn1Integer {
    auto _serial = X509_get0_serialNumber(this->as_ptr());
    auto serial = const_cast<ASN1_INTEGER *>(_serial);
    return asn1::Asn1Integer::ref(serial);
  }

  auto subject() const -> X509Name {
    auto subject = X509_get_subject_name(this->as_ptr());
    return X509Name::ref(subject);
  }

  auto issuer() const -> X509Name {
    auto issuer = X509_get_issuer_name(this->as_ptr());
    return X509Name::ref(issuer);
  }

  auto not_before() const -> asn1::Asn1Time {
    auto time = const_cast<ASN1_TIME *>(X509_get0_notBefore(this->as_ptr()));
    return asn1::Asn1Time::ref(time);
  }

  auto not_after() const -> asn1::Asn1Time {
    auto time = const_cast<ASN1_TIME *>(X509_get0_notAfter(this->as_ptr()));
    return asn1::Asn1Time::ref(time);
  }

  auto pub_key() const -> key::EvpPKey<key::Public> {
    auto pub = X509_get0_pubkey(this->as_ptr());
    return key::EvpPKey<key::Public>::ref(pub);
  }

  auto ext_count() const -> int32_t {
    return X509_get_ext_count(this->as_ptr());
  }

  auto key_usage() const -> KeyUsage {
    return KeyUsage::from(X509_get_key_usage(this->as_ptr()));
  }

  auto extended_key_usage() const -> ExtendedKeyUsage {
    return ExtendedKeyUsage::from(X509_get_extended_key_usage(this->as_ptr()));
  }
};

export enum class X509Version : long {
  V1,
  V2,
  V3
};

export class X509CertBuilder {
private:
  X509 *cert;

  X509CertBuilder() : cert(X509_new()) {}

public:
  static auto init() -> X509CertBuilder {
    return X509CertBuilder();
  }

  auto set_version(X509Version version) -> X509CertBuilder {
    X509_set_version(cert, static_cast<long>(version));
    return std::forward<X509CertBuilder>(*this);
  }

  auto set_serial(asn1::Asn1Integer &&cert_id) -> X509CertBuilder {
    X509_set_serialNumber(cert, cert_id.as_ptr());
    return std::forward<X509CertBuilder>(*this);
  }

  auto set_not_before(asn1::Asn1Time &&time) -> X509CertBuilder {
    X509_set1_notBefore(cert, time.as_ptr());
    return std::forward<X509CertBuilder>(*this);
  }

  auto set_not_after(asn1::Asn1Time &&time) -> X509CertBuilder {
    X509_set1_notAfter(cert, time.as_ptr());
    return std::forward<X509CertBuilder>(*this);
  }

  auto set_subject(X509Name &&name) -> X509CertBuilder {
    X509_set_subject_name(cert, name.as_ptr());
    return std::forward<X509CertBuilder>(*this);
  }

  auto set_issuer(X509Name &&name) -> X509CertBuilder {
    X509_set_issuer_name(cert, name.as_ptr());
    return std::forward<X509CertBuilder>(*this);
  }

  auto add_ext(X509Extension &&ext) -> X509CertBuilder {
    X509_add_ext(cert, ext.as_ptr(), -1);
    return std::forward<X509CertBuilder>(*this);
  }

  auto build(key::EvpPKey<key::Private> &&pkey) -> X509Certificate {
    X509_sign(cert, pkey.as_ptr(), EVP_sha256());
    return X509Certificate::own(cert);
  }

  // int add_ext(X509 *cert, int nid, const char *value) {
  //   X509_EXTENSION *ex;
  //   X509V3_CTX ctx;
  //   /* This sets the 'context' of the extensions. */
  //   /* No configuration database */
  //   X509V3_set_ctx_nodb(&ctx);
  //   /* Issuer and subject certs: both the target since it is self signed,
  //    * no request and no CRL
  //    */
  //   X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
  //   ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
  //   if (!ex)
  //     return 0;

  //   X509_add_ext(cert, ex, -1);
  //   X509_EXTENSION_free(ex);
  //   return 1;
  // }

  // auto test() {
  //   int nid;
  //   nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
  //   X509V3_EXT_add_alias(nid, NID_netscape_comment);
  //   add_ext(nullptr, nid, "example comment alias");
  // }
};

} // namespace openssl::x509
