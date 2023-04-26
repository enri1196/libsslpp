#pragma once

#include <openssl/x509.h>

#include "bio.hpp"
#include "x509/x509_certificate.hpp"

namespace openssl {

class LIBSSLPP_PUBLIC X509Store {
private:
  X509_STORE* m_ssl_type;

  X509Store() : m_ssl_type(X509_STORE_new()) {}

public:
  X509Store(const X509Store& store) {
    X509_STORE_up_ref(store.as_ptr());
    m_ssl_type = store.m_ssl_type;
  }
  X509Store(X509Store&& store) noexcept {
    m_ssl_type = store.m_ssl_type;
    store = nullptr;
  }
  auto operator=(const X509Store& store) -> X509Store& {
    if (this != &store) {
      X509_STORE_up_ref(store.as_ptr());
      m_ssl_type = store.m_ssl_type;
    }
    return *this;
  }
  auto operator=(X509Store&& store) noexcept -> X509Store& {
    if (this != &store) {
      m_ssl_type = store.m_ssl_type;
      store.m_ssl_type = nullptr;
    }
    return *this;
  }
  X509Store(X509_STORE* store) : m_ssl_type(store) {}
  ~X509Store() { X509_STORE_free(m_ssl_type); }

  auto as_ptr() const noexcept -> X509_STORE * { return m_ssl_type; }

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
    return {};
  }
};

} // namespace openssl
