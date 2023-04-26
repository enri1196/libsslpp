#pragma once

#include <openssl/x509v3.h>
#include <openssl/x509.h>

#include "asn1/asn1_octet_string.hpp"

namespace openssl {

enum class X509V3ExtensionNid : std::uint32_t {
  SUBJECT_ALT_NAME = NID_subject_alt_name,
  BASIC_CONSTRAINTS = NID_basic_constraints,
  KEY_USAGE = NID_key_usage,
  EXT_KEY_USAGE = NID_ext_key_usage,
  SUBJECT_KEY_IDENTIFIER = NID_subject_key_identifier,
  AUTHORITY_KEY_IDENTIFIER = NID_authority_key_identifier,
  PRIVATE_KEY_USAGE_PERIOD = NID_private_key_usage_period,
  CERTIFICATE_POLICIES = NID_certificate_policies,
  POLICY_MAPPINGS = NID_policy_mappings,
  POLICY_CONSTRAINTS = NID_policy_constraints,
  INHIBIT_ANY_POLICY = NID_inhibit_any_policy,
  NAME_CONSTRAINTS = NID_name_constraints,
  CRL_DISTRIBUTION_POINTS = NID_crl_distribution_points,
  CERTIFICATE_ISSUER = NID_certificate_issuer,
  SUBJECT_DIRECTORY_ATTRIBUTE = NID_subject_directory_attributes,
  SINFO_ACCESS = NID_sinfo_access,
  QC_STATEMENTS = NID_qcStatements,
  NETSCAPE_CERT_TYPE = NID_netscape_cert_type,
};

enum class KeyUsage : std::uint32_t {
  DIGITAL_SIGNATURE = KU_DIGITAL_SIGNATURE,
  NON_REPUDIATION = KU_NON_REPUDIATION,
  KEY_ENCIPHERMENT = KU_KEY_ENCIPHERMENT,
  DATA_ENCIPHERMENT = KU_DATA_ENCIPHERMENT,
  KEY_AGREEMENT = KU_KEY_AGREEMENT,
  KEY_CERT_SIGN = KU_KEY_CERT_SIGN,
  CRL_SIGN = KU_CRL_SIGN,
  ENCIPHER_ONLY = KU_ENCIPHER_ONLY,
  DECIPHER_ONLY = KU_DECIPHER_ONLY,
  ABSENT = UINT32_MAX
};

enum class ExtendedKeyUsage : std::uint32_t {
  SSL_SERVER = XKU_SSL_SERVER,
  SSL_CLIENT = XKU_SSL_CLIENT,
  SMIME = XKU_SMIME,
  CODE_SIGN = XKU_CODE_SIGN,
  OCSP_SIGN = XKU_OCSP_SIGN,
  TIMESTAMP = XKU_TIMESTAMP,
  DVCS = XKU_DVCS,
  ANYEKU = XKU_ANYEKU,
  ABSENT = UINT32_MAX
};

class LIBSSLPP_PUBLIC X509Extension {
private:
  using SSLPtr = std::shared_ptr<X509_EXTENSION>;
  SSLPtr m_ssl_type;

  X509Extension() : m_ssl_type(X509_EXTENSION_new(), X509_EXTENSION_free) {}

public:
  X509Extension(X509Extension &&) noexcept = default;
  X509Extension(const X509Extension &) = default;
  auto operator=(X509Extension &&) noexcept -> X509Extension & = default;
  auto operator=(const X509Extension &) -> X509Extension & = default;
  explicit X509Extension(X509_EXTENSION *ptr,
                      std::function<void(X509_EXTENSION *)> free_fn = X509_EXTENSION_free)
      : m_ssl_type(ptr, free_fn) {}
  ~X509Extension() = default;

  auto as_ptr() const noexcept -> X509_EXTENSION* { return m_ssl_type.get(); }

  static auto from(const X509V3ExtensionNid&& nid, const std::string_view&& data) -> Expected<X509Extension> {
    auto ext = X509Extension();
    auto ext_ptr = ext.as_ptr();
    auto octet = TRY(Asn1OctetString::from(std::move(data)));
    if (X509_EXTENSION_create_by_NID(&ext_ptr, static_cast<int>(nid), 0, octet.as_ptr()) == nullptr) {
      return Unexpected(SSLError(ErrorCode::ConversionError));
    }
    return {ext};
  }
};

}
