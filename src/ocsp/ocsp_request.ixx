module;

#include <memory>
#include <span>
#include <stdexcept>

#include <openssl/ocsp.h>

using namespace std;

export module ocsp:ocsp_req;

import evp;
import x509;

namespace openssl::ocsp {

static void oreq_own_free(OCSP_REQUEST *x) { OCSP_REQUEST_free(x); }
static void oreq_ref_free(OCSP_REQUEST *) {}

export class OCSPRequestBuilder;

export class OCSPRequest {
private:
  shared_ptr<OCSP_REQUEST> m_ssl_type;

  OCSPRequest() = delete;
  OCSPRequest(OCSP_REQUEST *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &oreq_own_free : &oreq_ref_free) {}

public:
  static auto own(OCSP_REQUEST *ref) -> OCSPRequest { return OCSPRequest(ref); }
  static auto ref(OCSP_REQUEST *ref) -> OCSPRequest {
    return OCSPRequest(ref, false);
  }

  static auto from(span<uint8_t> &&bytes) -> OCSPRequest {
    const unsigned char *bytes_data = bytes.data();
    auto req =
        d2i_OCSP_REQUEST(nullptr, &bytes_data, static_cast<long>(bytes.size()));
    if (req == nullptr) {
      throw runtime_error("OCSPRequest conversion from bytes Error");
    }
    return OCSPRequest(req);
  }

  auto as_ptr() const noexcept -> OCSP_REQUEST * { return m_ssl_type.get(); }
};

export class OCSPRequestBuilder {
private:
  OCSP_REQUEST *req{OCSP_REQUEST_new()};

  OCSPRequestBuilder() = default;

public:
  static auto init() -> OCSPRequestBuilder {
    return OCSPRequestBuilder();
  }

  auto set_nonce(span<uint8_t> &&bytes) -> OCSPRequestBuilder {
    OCSP_request_add1_nonce(req, const_cast<unsigned char *>(bytes.data()),
                            static_cast<int>(bytes.size()));
    return std::forward<OCSPRequestBuilder>(*this);
  }

  auto set_certificate(OCSP_CERTID *certId) -> OCSPRequestBuilder {
    OCSP_request_add0_id(req, certId);
    return std::forward<OCSPRequestBuilder>(*this);
  }

  auto set_issuer(x509::X509Certificate &&issuer) -> OCSPRequestBuilder {
    OCSP_request_add1_cert(req, issuer.as_ptr());
    return std::forward<OCSPRequestBuilder>(*this);
  }

  auto set_name(x509::X509Name &&name) -> OCSPRequestBuilder {
    OCSP_request_set1_name(req, name.as_ptr());
    return std::forward<OCSPRequestBuilder>(*this);
  }

  auto sign_and_build(const key::EvpPKey<key::Private> &pkey,
                      x509::X509Certificate &&signer,
                      const EVP_MD *dgst = EVP_sha256()) -> OCSPRequest {
    OCSP_request_sign(req, signer.as_ptr(), pkey.as_ptr(), dgst, nullptr, 0);
    return OCSPRequest::own(req);
  }
};

}  // namespace openssl::ocsp
