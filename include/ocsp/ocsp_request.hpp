#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/ocsp.h>

#include "internal/ssl_interface.hpp"

namespace openssl {

class OCSPRequest {
private:
  struct SSLDeleter {
    auto operator()(OCSP_REQUEST* ptr) { OCSP_REQUEST_free(ptr); }
  };
  using SSLPtr = std::unique_ptr<OCSP_REQUEST, SSLDeleter>;
  SSLPtr m_ssl_type;

  OCSPRequest() : m_ssl_type(OCSP_REQUEST_new()) {}

public:
  OCSPRequest(const OCSPRequest &) = delete;
  OCSPRequest(OCSPRequest &&) noexcept = default;
  auto operator=(const OCSPRequest &) -> OCSPRequest & = delete;
  auto operator=(OCSPRequest &&) noexcept -> OCSPRequest & = default;
  OCSPRequest(OCSP_REQUEST* req) : m_ssl_type(req) {};
  ~OCSPRequest() = default;

  auto as_ptr() const noexcept -> OCSP_REQUEST* { return m_ssl_type.get(); }

  static auto from(const std::vector<std::uint8_t>&& bytes) -> Expected<OCSPRequest> {
    auto bytes_data = bytes.data();
    auto req = d2i_OCSP_REQUEST(nullptr, &bytes_data, bytes.size());
    if (req == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return OCSPRequest(req);
  }
};

class OCSPRequestBuilder {
private:
  OCSP_REQUEST* req{OCSP_REQUEST_new()};

public:
  auto set_nonce(const std::vector<std::uint8_t>&& bytes) -> OCSPRequestBuilder {
    OCSP_request_add1_nonce(req, const_cast<unsigned char*>(bytes.data()), static_cast<int>(bytes.size()));
    return std::forward<OCSPRequestBuilder>(*this);
  }

  auto set_certificate(OCSP_CERTID *certId) -> OCSPRequestBuilder {
    OCSP_request_add0_id(req, certId);
    return std::forward<OCSPRequestBuilder>(*this);
  }

  auto set_issuer(X509 *issuer) -> OCSPRequestBuilder {
    OCSP_request_add1_cert(req, issuer);
    return std::forward<OCSPRequestBuilder>(*this);
  }

  auto build() -> OCSPRequest {
    return OCSPRequest(req);
  }
};

}  // namespace openssl
