#pragma once

#include "asn1/asn1_integer.hpp"
#include "asn1/asn1_time.hpp"
#include "evp_pkey.hpp"
#include "x509_name.hpp"
#include "x509_extension.hpp"

namespace openssl {

class X509CertificateBuilder;

class X509Certificate {
private:
  using SSLPtr = std::shared_ptr<X509>;
  SSLPtr m_ssl_type;

  X509Certificate() : m_ssl_type(X509_new(), X509_free) {}

public:
  X509Certificate(X509Certificate &&) noexcept = default;
  X509Certificate(const X509Certificate &) = default;
  auto operator=(X509Certificate &&) noexcept -> X509Certificate & = default;
  auto operator=(const X509Certificate &) -> X509Certificate & = default;
  explicit X509Certificate(X509 *ptr,
                           std::function<void(X509 *)> free_fn = X509_free)
      : m_ssl_type(ptr, free_fn) {}
  ~X509Certificate() = default;

  template <class Builder = X509CertificateBuilder>
    requires std::is_same_v<Builder, X509CertificateBuilder>
  static auto init() -> Builder {
    return Builder();
  }

  auto as_ptr() const noexcept -> X509 * { return m_ssl_type.get(); }

  static auto from(const std::vector<std::uint8_t> &&cert_bytes)
      -> Expected<X509Certificate> {
    auto bio_bytes = SSLBio::init();
    BIO_write(bio_bytes.as_ptr(), cert_bytes.data(),
              static_cast<int>(cert_bytes.size()));
    auto *cert =
        PEM_read_bio_X509(bio_bytes.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return {X509Certificate(cert)};
  }

  static auto from(const std::string_view &&cert_str)
      -> Expected<X509Certificate> {
    auto bio_str = SSLBio::init();
    bio_str.write_mem(std::move(cert_str));
    auto *cert = PEM_read_bio_X509(bio_str.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return {X509Certificate(cert)};
  }

  static auto from(const std::filesystem::path &&file_path)
      -> Expected<X509Certificate> {
    const auto bio_file = TRY(SSLBio::open_file(std::move(file_path)));
    auto cert = PEM_read_bio_X509(bio_file.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return {X509Certificate(cert)};
  }

  static auto from(const SSLBio &&bio_cert) -> Expected<X509Certificate> {
    auto cert = PEM_read_bio_X509(bio_cert.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError,
                                 "Couldn't parse certificate from bio"));
    }
    return {X509Certificate(cert)};
  }

  auto to_string() const -> Expected<std::string_view> {
    auto bio = SSLBio::init();
    if (X509_print_ex(bio.as_ptr(), this->as_ptr(), XN_FLAG_SEP_CPLUS_SPC,
                      X509_FLAG_COMPAT) == 0) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return bio.get_mem_ptr();
  }

  auto not_before() const -> Expected<const Asn1Time> {
    auto time = X509_get0_notBefore(this->as_ptr());
    if (time == nullptr) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    return {Asn1Time(const_cast<ASN1_TIME *>(time), [](ASN1_TIME*){})};
  }

  auto not_after() const -> Expected<const Asn1Time> {
    auto time = X509_get0_notAfter(this->as_ptr());
    if (time == nullptr) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    return {Asn1Time(const_cast<ASN1_TIME *>(time), [](ASN1_TIME*){})};
  }

  auto serial_number() const -> Expected<Asn1Integer> {
    ASN1_INTEGER *serial = X509_get_serialNumber(this->as_ptr());
    if (serial == nullptr) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    return {Asn1Integer(serial, [](ASN1_INTEGER*){})};
  }

  auto public_key() const -> Expected<EVPPkey<Public>> {
    auto pub_key = X509_get_pubkey(this->as_ptr());
    if (pub_key == nullptr) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    return {EVPPkey<Public>(pub_key, [](EVP_PKEY*){})};
  }

  auto issuer_name() const -> Expected<X509Name> {
    auto issuer = X509_get_issuer_name(this->as_ptr());
    if (issuer == nullptr) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    return {X509Name(issuer, [](X509_NAME*){})};
  }

  auto key_usage() -> Expected<KeyUsage> {
    auto key_usage = X509_get_key_usage(this->as_ptr());
    if (static_cast<KeyUsage>(key_usage) == KeyUsage::ABSENT) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    return {static_cast<KeyUsage>(key_usage)};
  }

  auto extended_key_usage() -> Expected<ExtendedKeyUsage> {
    auto key_usage = X509_get_extended_key_usage(this->as_ptr());
    if (static_cast<ExtendedKeyUsage>(key_usage) == ExtendedKeyUsage::ABSENT) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    return {static_cast<ExtendedKeyUsage>(key_usage)};
  }
}; // class X509Certificate

class X509CertificateBuilder {
private:
  X509 *cert{X509_new()};

  friend X509Certificate;

  X509CertificateBuilder() = default;

public:
  X509CertificateBuilder(const X509CertificateBuilder &) = delete;
  X509CertificateBuilder(X509CertificateBuilder &&) noexcept = default;
  auto operator=(const X509CertificateBuilder &)
      -> X509CertificateBuilder & = delete;
  auto operator=(X509CertificateBuilder &&) noexcept
      -> X509CertificateBuilder & = default;

  auto set_serial_number(const Asn1Integer &&integer) -> X509CertificateBuilder {
    X509_set_serialNumber(cert, integer.as_ptr());
    return std::forward<X509CertificateBuilder>(*this);
  }

  auto set_issuer_name(const X509Name &&name) -> X509CertificateBuilder {
    X509_set_issuer_name(cert, name.as_ptr());
    return std::forward<X509CertificateBuilder>(*this);
  }

  auto set_subject(const X509Name &&name) -> X509CertificateBuilder {
    X509_set_subject_name(cert, name.as_ptr());
    return std::forward<X509CertificateBuilder>(*this);
  }

  auto set_extension(const X509Extension&& ex) -> X509CertificateBuilder {
    X509_add_ext(cert, ex.as_ptr(), -1);
    return std::forward<X509CertificateBuilder>(*this);
  }

  auto sign(const EVPPkey<Private> &&key) -> X509Certificate {
    X509_sign(cert, key.as_ptr(), nullptr);
    return X509Certificate(cert);
  }
}; // class X509CertificateBuilder

} // namespace openssl
