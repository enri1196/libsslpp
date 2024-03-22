module;

#include <memory>
#include <vector>
#include <span>
#include <string>

#include <openssl/safestack.h>
#include <openssl/ts.h>

using namespace std;

export module tsp:tsp_req;

import asn1;
import bio;

namespace openssl::ts {

static void treq_own_free(TS_REQ *x) { TS_REQ_free(x); }
static void treq_ref_free(TS_REQ *) {}

export class TSRequest {
private:
  shared_ptr<TS_REQ> m_ssl_type;

  TSRequest() = delete;
  TSRequest(TS_REQ *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &treq_own_free : &treq_ref_free) {}

public:
  static auto own(TS_REQ *ref) -> TSRequest { return TSRequest(ref); }
  static auto ref(TS_REQ *ref) -> TSRequest {
    return TSRequest(ref, false);
  }

  auto as_ptr() const noexcept -> TS_REQ* { return m_ssl_type.get(); }

  static auto from(span<uint8_t> &&bytes) -> TSRequest {
    const unsigned char *bytes_data = bytes.data();
    auto req = d2i_TS_REQ(nullptr, &bytes_data, static_cast<long>(bytes.size()));
    if (req == nullptr) {
      throw std::runtime_error("TSRequest conversion from bytes Error");
    }
    return TSRequest(req);
  }

  static auto from(bio::SSLBio &&bio) -> TSRequest {
    auto req = d2i_TS_REQ_bio(bio.as_ptr(), nullptr);
    if (req == nullptr) {
      throw std::runtime_error("TSRequest conversion from bio Error");
    }
    return TSRequest(req);
  }

  auto exts() const -> STACK_OF(X509_EXTENSION)* {
    auto stack = TS_REQ_get_exts(this->as_ptr());
    return stack;
  }

  auto msg_imprint() const -> TS_MSG_IMPRINT* {
    auto msg = TS_REQ_get_msg_imprint(this->as_ptr());
    return msg;
  }

  auto nonce() const -> asn1::Asn1Integer {
    auto nonce = TS_REQ_get_nonce(this->as_ptr());
    return asn1::Asn1Integer::ref(const_cast<ASN1_INTEGER*>(nonce));
  }

  auto policy_id() const -> ASN1_OBJECT* {
    auto id = TS_REQ_get_policy_id(this->as_ptr());
    return id;
  }

  auto to_string() const -> string {
    auto bio = bio::SSLBio::memory();
    TS_REQ_print_bio(bio.as_ptr(), this->as_ptr());
    return bio.get_mem_ptr();
  }

  auto to_bytes() const -> vector<uint8_t> {
    return {};
  }
};

export class TSRequestBuilder {
private:
  TS_REQ *req{TS_REQ_new()};

  TSRequestBuilder() = default;

public:
  static auto init() -> TSRequestBuilder {
    return TSRequestBuilder();
  }

  auto set_version(long version) -> TSRequestBuilder {
    TS_REQ_set_version(req, version);
    return std::forward<TSRequestBuilder>(*this);
  }

  auto set_policy_id(const ASN1_OBJECT* policy_id) -> TSRequestBuilder {
    TS_REQ_set_policy_id(req, policy_id);
    return std::forward<TSRequestBuilder>(*this);
  }

  auto set_nonce(asn1::Asn1Integer&& nonce) -> TSRequestBuilder {
    TS_REQ_set_nonce(req, nonce.as_ptr());
    return std::forward<TSRequestBuilder>(*this);
  }

  auto set_cert_request(bool cert_request) -> TSRequestBuilder {
    TS_REQ_set_cert_req(req, cert_request);
    return std::forward<TSRequestBuilder>(*this);
  }
  
  auto build() -> TSRequest {
    return TSRequest::own(req);
  }
};

}  // namespace openssl::ts
