#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "internal/ssl_interface.hpp"
#include "asn1/asn1_time.hpp"
#include "asn1/asn1_integer.hpp"

namespace openssl {

class X509CertificateBuilder;
class X509CertificateView;

class LIBSSLPP_PUBLIC X509Certificate {
private:
  using SSLPtr = std::shared_ptr<X509>;
  SSLPtr m_ssl_type;

  X509Certificate() : m_ssl_type(X509_new(), X509_free) {}

  friend X509CertificateView;

public:
  X509Certificate(X509Certificate &&) noexcept = default;
  X509Certificate(const X509Certificate &) = default;
  auto operator=(X509Certificate &&) noexcept -> X509Certificate & = default;
  auto operator=(const X509Certificate &) -> X509Certificate & = default;
  explicit X509Certificate(X509 *ptr) : m_ssl_type(ptr, X509_free) {}
  ~X509Certificate();

  template<class Builder>
  requires std::is_same_v<Builder, X509CertificateBuilder>
  static auto init() -> Builder {
    return Builder();
  }

  auto as_ptr() const noexcept -> X509* { return m_ssl_type.get(); }

  static auto parse(const std::vector<std::uint8_t>&& cert_bytes) -> Expected<X509Certificate> {
    auto bio_bytes = SSLBio::init();
    BIO_write(bio_bytes.as_ptr(), cert_bytes.data(), static_cast<int>(cert_bytes.size()));
    auto* cert = PEM_read_bio_X509(bio_bytes.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return Expected<X509Certificate>(X509Certificate(cert));
  }

  static auto parse(const std::string_view&& cert_str) -> Expected<X509Certificate> {
    auto bio_str = SSLBio::init();
    BIO_write(bio_str.as_ptr(), cert_str.data(), static_cast<int>(cert_str.length()));
    auto* cert = PEM_read_bio_X509(bio_str.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return Expected<X509Certificate>(X509Certificate(cert));
  }

  static auto parse(const std::filesystem::path&& file_path) -> Expected<X509Certificate> {
    const auto bio_file = TRY(SSLBio::open_file(std::move(file_path)));
    auto cert = PEM_read_bio_X509(bio_file.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return Expected<X509Certificate>(X509Certificate(cert));
  }

  static auto parse(const SSLBio&& bio_cert) -> Expected<X509Certificate> {
    auto cert = PEM_read_bio_X509(bio_cert.as_ptr(), nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError, "Couldn't parse certificate from bio"));
    }
    return Expected<X509Certificate>(X509Certificate(cert));
  }

  auto to_string() const -> Expected<std::string_view> {
    auto bio = SSLBio::init();
    if (X509_print_ex(bio.as_ptr(), this->as_ptr(), XN_FLAG_SEP_CPLUS_SPC, X509_FLAG_COMPAT) == 0) {
            return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return bio.get_mem_data();
  }

  auto not_before() const -> Expected<Asn1Time> {
    auto time = X509_get0_notBefore(this->as_ptr());
    if (time == nullptr) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    // take ownership of time to prevent double free
    auto ans1_time = const_cast<ASN1_TIME *>(ASN1_STRING_dup(time));
    return Expected<Asn1Time>(Asn1Time(ans1_time));
  }

  auto not_after() const -> Expected<Asn1Time> {
    auto time = X509_get0_notAfter(this->as_ptr());
    // take ownership of time to prevent double free
    if (time == nullptr) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    // take ownership of time to prevent double free
    auto ans1_time = const_cast<ASN1_TIME *>(ASN1_STRING_dup(time));
    return Expected<Asn1Time>(Asn1Time(ans1_time));
  }

  auto serial_number() const -> Expected<Asn1Integer> {
    ASN1_INTEGER *serial = X509_get_serialNumber(this->as_ptr());
    return Expected<Asn1Integer>(Asn1Integer(serial));
  }

  auto get_public_key() -> EVP_PKEY* {
    return X509_get_pubkey(this->as_ptr());
  }
};  // class X509Certificate

class LIBSSLPP_PUBLIC X509CertificateBuilder {
private:
  X509* cert{X509_new()};

public:
  X509CertificateBuilder() = delete;
  X509CertificateBuilder(const X509CertificateBuilder &) = delete;
  X509CertificateBuilder(X509CertificateBuilder &&) noexcept = default;
  auto operator=(const X509CertificateBuilder &) -> X509CertificateBuilder & = delete;
  auto operator=(X509CertificateBuilder &&) noexcept -> X509CertificateBuilder & = default;

  auto set_serial_number() -> X509CertificateBuilder {
    X509_set_serialNumber(cert, nullptr);
    return std::forward<X509CertificateBuilder>(*this);
  }

  auto set_issuer_name() -> X509CertificateBuilder {
    X509_set_issuer_name(cert, nullptr);
    return std::forward<X509CertificateBuilder>(*this);
  }

  auto set_subject() -> X509CertificateBuilder {
    X509_set_subject_name(cert, nullptr);
    return std::forward<X509CertificateBuilder>(*this);
  }

  auto sign(EVP_PKEY* key) -> X509Certificate {
    X509_sign(cert, key, nullptr);
    return X509Certificate(cert);
  }
};  // class X509CertificateBuilder

}  // namespace openssl
