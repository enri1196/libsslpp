#include "x509/x509_certificate.hpp"
#include "openssl/x509.h"

namespace openssl {

X509Certificate::X509Certificate(X509Certificate&& x509) noexcept {
    m_ssl_type = x509.m_ssl_type;
    x509.m_ssl_type = nullptr;
}

X509Certificate::X509Certificate(const X509Certificate &x509) {
    X509_up_ref(x509.as_ptr());
    m_ssl_type = x509.m_ssl_type;
}
auto X509Certificate::operator=(X509Certificate &&x509) noexcept -> X509Certificate & {
  if (this != &x509) {
    m_ssl_type = x509.m_ssl_type;
    x509.m_ssl_type = nullptr;
  }
  return *this;
}
auto X509Certificate::operator=(const X509Certificate &x509) -> X509Certificate & {
  if (this != &x509) {
    X509_up_ref(x509.as_ptr());
    m_ssl_type = x509.m_ssl_type;
  }
  return *this;
}

X509Certificate::~X509Certificate() { X509_free(m_ssl_type); }

template <class Builder>
requires std::is_same_v<Builder, X509CertificateBuilder>
auto X509Certificate::init() -> Builder {
  return Builder();
}

auto X509Certificate::as_ptr() const noexcept -> X509 * { return m_ssl_type; }

auto X509Certificate::from(const std::vector<std::uint8_t> &&cert_bytes)
    -> Expected<X509Certificate> {
  auto bio_bytes = SSLBio::init();
  bio_bytes.write_mem(std::move(cert_bytes));
  auto *cert =
      PEM_read_bio_X509(bio_bytes.as_ptr(), nullptr, nullptr, nullptr);
  if (cert == nullptr) {
    return Unexpected(SSLError(ErrorCode::ParseError));
  }
  return {X509Certificate(cert)};
}

auto X509Certificate::from(const std::string_view &&cert_str)
    -> Expected<X509Certificate> {
  auto bio_str = SSLBio::init();
  bio_str.write_mem(std::move(cert_str));
  auto *cert = PEM_read_bio_X509(bio_str.as_ptr(), nullptr, nullptr, nullptr);
  if (cert == nullptr) {
    return Unexpected(SSLError(ErrorCode::ParseError));
  }
  return {X509Certificate(cert)};
}

auto X509Certificate::from(const std::filesystem::path &&file_path)
    -> Expected<X509Certificate> {
  const auto bio_file = TRY(SSLBio::open_file(std::move(file_path)));
  auto cert = PEM_read_bio_X509(bio_file.as_ptr(), nullptr, nullptr, nullptr);
  if (cert == nullptr) {
    return Unexpected(SSLError(ErrorCode::ParseError));
  }
  return {X509Certificate(cert)};
}

auto X509Certificate::from(const SSLBio &&bio_cert) -> Expected<X509Certificate> {
  auto cert = PEM_read_bio_X509(bio_cert.as_ptr(), nullptr, nullptr, nullptr);
  if (cert == nullptr) {
    return Unexpected(SSLError(ErrorCode::ParseError,
                                "Couldn't parse certificate from bio"));
  }
  return {X509Certificate(cert)};
}

auto X509Certificate::to_string() const -> Expected<std::string_view> {
  auto bio = SSLBio::init();
  if (X509_print_ex(bio.as_ptr(), this->as_ptr(), XN_FLAG_SEP_CPLUS_SPC,
                    X509_FLAG_COMPAT) == 0) {
    return Unexpected(SSLError(ErrorCode::ParseError));
  }
  return bio.get_mem_ptr();
}

auto X509Certificate::not_before() const -> Expected<Asn1Time> {
  auto time = X509_get_notBefore(this->as_ptr());
  if (time == nullptr) {
    return Unexpected(SSLError(ErrorCode::AccesError));
  }
  return {Asn1Time(time, [](ASN1_TIME*){})};
}

auto X509Certificate::not_after() const -> Expected<Asn1Time> {
  auto time = X509_get_notAfter(this->as_ptr());
  if (time == nullptr) {
    return Unexpected(SSLError(ErrorCode::AccesError));
  }
  return {Asn1Time(time, [](ASN1_TIME*){})};
}

auto X509Certificate::serial_number() const -> Expected<Asn1Integer> {
  ASN1_INTEGER *serial = X509_get_serialNumber(this->as_ptr());
  if (serial == nullptr) {
    return Unexpected(SSLError(ErrorCode::AccesError));
  }
  return {Asn1Integer(serial, [](ASN1_INTEGER*){})};
}

auto X509Certificate::public_key() const -> Expected<EVPPkey<Public>> {
  auto pub_key = X509_get_pubkey(this->as_ptr());
  if (pub_key == nullptr) {
    return Unexpected(SSLError(ErrorCode::AccesError));
  }
  return {EVPPkey<Public>(pub_key)};
}

auto X509Certificate::issuer_name() const -> Expected<X509Name> {
  auto issuer = X509_get_issuer_name(this->as_ptr());
  if (issuer == nullptr) {
    return Unexpected(SSLError(ErrorCode::AccesError));
  }
  return {X509Name(issuer, [](X509_NAME*){})};
}

auto X509Certificate::key_usage() -> Expected<KeyUsage> {
  auto key_usage = X509_get_key_usage(this->as_ptr());
  if (static_cast<KeyUsage>(key_usage) == KeyUsage::ABSENT) {
    return Unexpected(SSLError(ErrorCode::AccesError));
  }
  return {static_cast<KeyUsage>(key_usage)};
}

auto X509Certificate::extended_key_usage() -> Expected<ExtendedKeyUsage> {
  auto key_usage = X509_get_extended_key_usage(this->as_ptr());
  if (static_cast<ExtendedKeyUsage>(key_usage) == ExtendedKeyUsage::ABSENT) {
    return Unexpected(SSLError(ErrorCode::AccesError));
  }
  return {static_cast<ExtendedKeyUsage>(key_usage)};
}

}
