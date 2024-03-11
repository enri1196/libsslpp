module;

#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>

#include <openssl/ocsp.h>

export module ocsp:ocsp_resp;

namespace openssl::ocsp {

static void oresp_own_free(OCSP_RESPONSE *x) { OCSP_RESPONSE_free(x); }
static void oresp_ref_free(OCSP_RESPONSE *x) {}

export class OCSPResponse {
private:
  std::shared_ptr<OCSP_RESPONSE> m_ssl_type;

  OCSPResponse() = delete;
  OCSPResponse(OCSP_RESPONSE *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &oresp_own_free : &oresp_ref_free) {}

public:
  static auto own(OCSP_RESPONSE *ref) -> OCSPResponse {
    return OCSPResponse(ref);
  }
  static auto ref(OCSP_RESPONSE *ref) -> OCSPResponse {
    return OCSPResponse(ref, false);
  }

  static auto from(std::span<std::uint8_t> &&bytes) -> OCSPResponse {
    const unsigned char *bytes_data = bytes.data();
    auto req = d2i_OCSP_RESPONSE(nullptr, &bytes_data,
                                 static_cast<long>(bytes.size()));
    if (req == nullptr) {
      throw std::runtime_error("OCSPResponse conversion from bytes Error");
    }
    return OCSPResponse(req);
  }

  auto as_ptr() const noexcept -> OCSP_RESPONSE * { return m_ssl_type.get(); }
};

} // namespace openssl::ocsp
