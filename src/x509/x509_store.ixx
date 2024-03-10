module;

#include <memory>
#include <stdexcept>

#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

export module x509:x509_store;

import :x509_cert;

namespace openssl::x509 {

static void store_own_free(X509_STORE *x) { X509_STORE_free(x); }
static void store_ref_free(X509_STORE *x) {}

export class X509Store {
private:
  std::shared_ptr<X509_STORE> m_ssl_type;

  X509Store() : m_ssl_type(X509_STORE_new(), &store_own_free) {}
  X509Store(X509_STORE *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &store_own_free : &store_ref_free) {}

public:
  static auto own(X509_STORE *ref) -> X509Store { return X509Store(ref); }
  static auto ref(X509_STORE *ref) -> X509Store { return X509Store(ref, false); }

  static auto init() -> X509Store {
    return X509Store();
  }

  auto as_ptr() const noexcept -> X509_STORE * { return m_ssl_type.get(); }

  auto len() const -> std::size_t {
    auto sk = X509_STORE_get0_objects(this->as_ptr());
    return static_cast<std::size_t>(sk->stack.num);
  }

  auto add_cert(X509Certificate&& cert) const -> void {
    if (X509_STORE_add_cert(this->as_ptr(), cert.as_ptr()) <= 0) {
      throw std::runtime_error("Could not add certificate");
    }
  }
};

} // namespace openssl::x509
