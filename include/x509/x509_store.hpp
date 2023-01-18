#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

#include <openssl/x509.h>

#include "bio.hpp"
#include "internal/ssl_interface.hpp"
#include "x509/x509_certificate.hpp"

namespace openssl {

class X509Store {
private:
  using SSLPtr = std::shared_ptr<X509_STORE>;
  SSLPtr m_ssl_type;

  X509Store() : m_ssl_type(X509_STORE_new(), X509_STORE_free) {}

public:
  X509Store(const X509Store &) = default;
  X509Store(X509Store &&) noexcept = default;
  auto operator=(const X509Store &) -> X509Store & = default;
  auto operator=(X509Store &&) noexcept -> X509Store & = default;
  explicit X509Store(X509_STORE *ptr,
                    std::function<void(X509_STORE *)> free_fn = X509_STORE_free)
      : m_ssl_type(ptr, free_fn) {}
  ~X509Store() = default;

  auto as_ptr() const noexcept -> X509_STORE * { return m_ssl_type.get(); }

  static auto init() -> X509Store {
    return X509Store();
  }

  auto len() const -> std::size_t {
    auto sk = X509_STORE_get0_objects(this->as_ptr());
    return static_cast<std::size_t>(sk->stack.num);
  }

  auto add_cert(const X509Certificate&& cert) const -> Expected<void> {
    if (X509_STORE_add_cert(this->as_ptr(), cert.as_ptr()) <= 0) {
      return Unexpected(SSLError(ErrorCode::AccesError));
    }
    X509_up_ref(cert.as_ptr());
    return {};
  }
};

} // namespace openssl
