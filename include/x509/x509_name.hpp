#pragma once

#include <string_view>

#include <openssl/x509.h>

#include "bio.hpp"

namespace openssl {

class X509Name {
private:
  struct SSLDeleter {
    auto operator()(X509_NAME* ptr) { X509_NAME_free(ptr); }
  };
  using SSLPtr = std::unique_ptr<X509_NAME, SSLDeleter>;
  SSLPtr m_ssl_type;

  X509Name() : m_ssl_type(X509_NAME_new()) {}

public:
  X509Name(const X509Name &) = delete;
  X509Name(X509Name &&) noexcept = default;
  auto operator=(const X509Name &) -> X509Name & = delete;
  auto operator=(X509Name &&) noexcept -> X509Name & = default;
  explicit X509Name(X509_NAME *ptr) : m_ssl_type(ptr) {}
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
