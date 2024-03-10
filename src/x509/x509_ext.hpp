#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>

#include <openssl/x509v3.h>
#include <openssl/x509.h>

#include "../asn1/asn1_octet_string.hpp"

namespace openssl::x509 {

static void xext_own_free(X509_EXTENSION *x) { X509_EXTENSION_free(x); }
static void xext_ref_free(X509_EXTENSION *x) {}

enum class X509V3ExtensionNid : std::uint32_t {
  SUBJECT_ALT_NAME              = NID_subject_alt_name,
  BASIC_CONSTRAINTS             = NID_basic_constraints,
  KEY_USAGE                     = NID_key_usage,
  EXT_KEY_USAGE                 = NID_ext_key_usage,
  SUBJECT_KEY_IDENTIFIER        = NID_subject_key_identifier,
  AUTHORITY_KEY_IDENTIFIER      = NID_authority_key_identifier,
  PRIVATE_KEY_USAGE_PERIOD      = NID_private_key_usage_period,
  CERTIFICATE_POLICIES          = NID_certificate_policies,
  POLICY_MAPPINGS               = NID_policy_mappings,
  POLICY_CONSTRAINTS            = NID_policy_constraints,
  INHIBIT_ANY_POLICY            = NID_inhibit_any_policy,
  NAME_CONSTRAINTS              = NID_name_constraints,
  CRL_DISTRIBUTION_POINTS       = NID_crl_distribution_points,
  CERTIFICATE_ISSUER            = NID_certificate_issuer,
  SUBJECT_DIRECTORY_ATTRIBUTE   = NID_subject_directory_attributes,
  SINFO_ACCESS                  = NID_sinfo_access,
  QC_STATEMENTS                 = NID_qcStatements,
  NETSCAPE_CERT_TYPE            = NID_netscape_cert_type,
};

class X509Extension {
private:
  std::shared_ptr<X509_EXTENSION> m_ssl_type;

  X509Extension() = delete;
  X509Extension(X509_EXTENSION *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &xext_own_free : &xext_ref_free) {}

public:
  static auto own(X509_EXTENSION *ref) -> X509Extension { return X509Extension(ref); }
  static auto ref(X509_EXTENSION *ref) -> X509Extension { return X509Extension(ref, false); }

  static auto from(X509V3ExtensionNid nid, std::string_view&& data) -> X509Extension {
    auto ext = X509_EXTENSION_new();
    auto octet = asn1::Asn1OctetString::from(std::move(data));
    if (X509_EXTENSION_create_by_NID(&ext, static_cast<int>(nid), 0, octet.as_ptr()) == nullptr) {
      throw std::runtime_error("X509Extension conversion from string Error");
    }
    return X509Extension(ext);
  }

  static auto from(std::span<std::uint8_t> &&bytes) -> X509Extension {
    const unsigned char *ext_bytes = bytes.data();
    auto ext = d2i_X509_EXTENSION(nullptr, &ext_bytes, (long)bytes.size());
    return X509Extension(ext);
  }

  auto as_ptr() const noexcept -> X509_EXTENSION* { return m_ssl_type.get(); }
};

class ExtensionBuilder {

};

}  // namespace openssl::x509
