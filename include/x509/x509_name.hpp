#pragma once

#include <string_view>

#include <openssl/x509.h>

#include "bio.hpp"

namespace openssl {

class X509Name {
private:
  using SSLPtr = std::shared_ptr<X509_NAME>;
  SSLPtr m_ssl_type;

  X509Name() : m_ssl_type(X509_NAME_new(), X509_NAME_free) {}

public:
  X509Name(const X509Name &) = default;
  X509Name(X509Name &&) noexcept = default;
  auto operator=(const X509Name &) -> X509Name & = default;
  auto operator=(X509Name &&) noexcept -> X509Name & = default;
  explicit X509Name(X509_NAME *ptr) : m_ssl_type(ptr, X509_NAME_free) {}
  ~X509Name() = default;

  auto as_ptr() const noexcept -> X509_NAME* {
    return m_ssl_type.get();
  }

  auto to_string() -> Expected<std::string_view> {
    auto bio = SSLBio::init();
    X509_NAME_print_ex(bio.as_ptr(), this->as_ptr(), 0, XN_FLAG_ONELINE);
    return bio.get_mem_ptr();
  }
};

}
