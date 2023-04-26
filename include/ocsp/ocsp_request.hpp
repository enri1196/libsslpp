#pragma once

#include <openssl/ocsp.h>
#include <openssl/evp.h>

#include "evp_pkey.hpp"
#include "x509/x509_certificate.hpp"
#include "x509/x509_name.hpp"

namespace openssl::ocsp {

class OCSPRequestBuilder;

class LIBSSLPP_PUBLIC OCSPRequest {
private:
  using FreeFn = decltype([](OCSP_REQUEST* ptr){OCSP_REQUEST_free(ptr);});
  using SSLPtr = std::unique_ptr<OCSP_REQUEST, FreeFn>;
  SSLPtr m_ssl_type;

  OCSPRequest() : m_ssl_type(OCSP_REQUEST_new()) {}

public:
  OCSPRequest(const OCSPRequest &) = delete;
  OCSPRequest(OCSPRequest &&) noexcept = default;
  auto operator=(const OCSPRequest &) -> OCSPRequest & = delete;
  auto operator=(OCSPRequest &&) noexcept -> OCSPRequest & = default;
  explicit OCSPRequest(OCSP_REQUEST *ptr) : m_ssl_type(ptr) {}
  ~OCSPRequest() = default;

  auto as_ptr() const noexcept -> OCSP_REQUEST* { return m_ssl_type.get(); }

  template <class Builder>
  requires std::is_same_v<Builder, OCSPRequestBuilder>
  static auto init() -> Builder {
    return Builder();
  }

  static auto from(const std::vector<std::uint8_t>&& bytes) -> Expected<OCSPRequest> {
    auto bytes_data = bytes.data();
    auto req = d2i_OCSP_REQUEST(nullptr, &bytes_data, static_cast<long>(bytes.size()));
    if (req == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return {OCSPRequest(req)};
  }
};

class OCSPRequestBuilder {
private:
  OCSP_REQUEST* req{OCSP_REQUEST_new()};

public:
  OCSPRequestBuilder() = delete;
  OCSPRequestBuilder(const OCSPRequestBuilder &) = delete;
  OCSPRequestBuilder(OCSPRequestBuilder &&) noexcept = default;
  auto operator=(const OCSPRequestBuilder &) -> OCSPRequestBuilder & = delete;
  auto operator=(OCSPRequestBuilder &&) noexcept -> OCSPRequestBuilder & = default;

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

  auto set_name(const X509Name&& name) -> OCSPRequestBuilder {
    OCSP_request_set1_name(req, name.as_ptr());
    return std::forward<OCSPRequestBuilder>(*this);
  }

  auto sign(const EVPPkey<Private> pkey, const X509Certificate&& signer, const EVP_MD* dgst = EVP_sha256()) -> OCSPRequestBuilder {
    OCSP_request_sign(req, signer.as_ptr(), pkey.as_ptr(), dgst, nullptr, 0);
    return std::forward<OCSPRequestBuilder>(*this);
  }

  auto build() -> OCSPRequest {
    return OCSPRequest(req);
  }
};

}  // namespace openssl
