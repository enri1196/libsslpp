#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/ocsp.h>

#include "internal/ssl_interface.hpp"
#include "openssl/ossl_typ.h"

namespace openssl {

class OCSPResponse {
private:
  using SSLPtr = std::shared_ptr<OCSP_RESPONSE>;
  SSLPtr m_ssl_type;

  OCSPResponse() : m_ssl_type(OCSP_RESPONSE_new(), OCSP_RESPONSE_free) {}

public:
  OCSPResponse(const OCSPResponse &) = default;
  OCSPResponse(OCSPResponse &&) noexcept = default;
  auto operator=(const OCSPResponse &) -> OCSPResponse & = default;
  auto operator=(OCSPResponse &&) noexcept -> OCSPResponse & = default;
  explicit OCSPResponse(OCSP_RESPONSE *ptr,
                        std::function<void(OCSP_RESPONSE *)> free_fn = OCSP_RESPONSE_free)
      : m_ssl_type(ptr, free_fn) {}
  ~OCSPResponse() = default;

  auto as_ptr() const noexcept -> OCSP_RESPONSE* { return m_ssl_type.get(); }

  static auto from(const std::vector<std::uint8_t>&& bytes) -> Expected<OCSPResponse> {
    auto bytes_data = bytes.data();
    auto req = d2i_OCSP_RESPONSE(nullptr, &bytes_data, bytes.size());
    if (req == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return OCSPResponse(req);
  }
};

}  // namespace openssl
