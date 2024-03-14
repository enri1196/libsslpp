module;

#include <memory>
#include <span>
#include <stdexcept>

#include <openssl/x509.h>

using namespace std;

export module x509:x509_req;

namespace openssl::x509 {

static void xreq_own_free(X509_REQ *x) { X509_REQ_free(x); }
static void xreq_ref_free(X509_REQ *) {}

export class X509Request {
private:
  shared_ptr<X509_REQ> m_ssl_type;

  X509Request() = delete;
  X509Request(X509_REQ *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &xreq_own_free : &xreq_ref_free) {}

public:
  static auto own(X509_REQ *ref) -> X509Request { return X509Request(ref); }
  static auto ref(X509_REQ *ref) -> X509Request { return X509Request(ref, false); }

  auto as_ptr() const -> X509_REQ* { return m_ssl_type.get(); }

  static auto from(span<uint8_t>&& bytes) -> X509Request {
    const unsigned char *bytes_data = bytes.data();
    auto req = d2i_X509_REQ(nullptr, &bytes_data, static_cast<long>(bytes.size()));
    if (req == nullptr) {
      throw runtime_error("X509Request conversion from bytes Error");
    }
    return X509Request(req);
  }
};

} // namespace openssl
