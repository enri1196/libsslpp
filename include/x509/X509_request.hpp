#include "openssl/x509.h"

#include "internal/ssl_interface.hpp"
#include <memory>

namespace openssl {

class X509Request {
private:
  using SSLptr = std::shared_ptr<X509_REQ>;
  SSLptr m_ssl_type;

  X509Request() : m_ssl_type(X509_REQ_new(), X509_REQ_free) {}

public:
  X509Request(X509Request &&x509) noexcept = default;
  X509Request(const X509Request &x509) = default;
  auto operator=(X509Request &&x509) noexcept -> X509Request & = default;
  auto operator=(const X509Request &x509) -> X509Request & = default;
  explicit X509Request(X509_REQ *ptr,
                       std::function<void(X509_REQ *)> free_fn = X509_REQ_free)
      : m_ssl_type(ptr, free_fn) {}
  ~X509Request() = default;

  auto as_ptr() const -> X509_REQ* { return m_ssl_type.get(); }

  static auto from(const std::vector<std::uint8_t>&& buf) -> Expected<X509Request> {
    X509_REQ* ptr = X509_REQ_new();
    if (d2i_X509_REQ(&ptr, (const unsigned char **)buf.data(), buf.size()) == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return X509Request(ptr);
  }
};

} // namespace openssl
