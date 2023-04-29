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

}
