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
  struct SSLDeleter {
    auto operator()(OCSP_RESPONSE* ptr) { OCSP_RESPONSE_free(ptr); }
  };
  using SSLPtr = std::unique_ptr<OCSP_RESPONSE, SSLDeleter>;
  SSLPtr m_ssl_type;

  OCSPResponse() : m_ssl_type(OCSP_RESPONSE_new()) {}

public:
  OCSPResponse(const OCSPResponse &) = delete;
  OCSPResponse(OCSPResponse &&) noexcept = default;
  auto operator=(const OCSPResponse &) -> OCSPResponse & = delete;
  auto operator=(OCSPResponse &&) noexcept -> OCSPResponse & = default;
  OCSPResponse(OCSP_RESPONSE* resp) : m_ssl_type(resp) {}
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
