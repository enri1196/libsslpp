#pragma once

#include <openssl/safestack.h>
#include <openssl/ts.h>

#include "asn1/asn1_integer.hpp"

namespace openssl {

class TSRequestBuilder;

class TSRequest {
private:
  using SSLPtr = std::shared_ptr<TS_REQ>;
  SSLPtr m_ssl_type;

  TSRequest() : m_ssl_type(TS_REQ_new(), TS_REQ_free) {}

public:
  TSRequest(const TSRequest &) = default;
  TSRequest(TSRequest &&) noexcept = default;
  auto operator=(const TSRequest &) -> TSRequest & = default;
  auto operator=(TSRequest &&) noexcept -> TSRequest & = default;
  explicit TSRequest(TS_REQ *ptr,
                       std::function<void(TS_REQ *)> free_fn = TS_REQ_free)
      : m_ssl_type(ptr, free_fn) {}
  ~TSRequest() = default;

  auto as_ptr() const noexcept -> TS_REQ* { return m_ssl_type.get(); }

  template <class Builder = TSRequestBuilder>
    requires std::is_same_v<Builder, TSRequestBuilder>
  static auto init() -> Builder {
    return Builder();
  }

  static auto from(const std::vector<std::uint8_t>&& bytes) -> Expected<TSRequest> {
    auto bytes_data = bytes.data();
    auto req = d2i_TS_REQ(nullptr, &bytes_data, bytes.size());
    if (req == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
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

  auto nonce() const -> const Asn1Integer {
    auto nonce = TS_REQ_get_nonce(this->as_ptr());
    return Asn1Integer(const_cast<ASN1_INTEGER*>(nonce), [](ASN1_INTEGER*){});
  }

  auto policy_id() const -> ASN1_OBJECT* {
    auto id = TS_REQ_get_policy_id(this->as_ptr());
    return id;
  }
};

class TSRequestBuilder {
private:
  TS_REQ *req{TS_REQ_new()};

  friend TSRequest;

  TSRequestBuilder() = default;

public:
  TSRequestBuilder(const TSRequestBuilder &) = delete;
  TSRequestBuilder(TSRequestBuilder &&) noexcept = default;
  auto operator=(const TSRequestBuilder &) -> TSRequestBuilder & = delete;
  auto operator=(TSRequestBuilder &&) noexcept -> TSRequestBuilder & = default;

  auto set_version(long version) -> TSRequestBuilder {
    TS_REQ_set_version(req, version);
    return std::forward<TSRequestBuilder>(*this);
  }

  auto set_policy_id(const ASN1_OBJECT* policy_id) -> TSRequestBuilder {
    TS_REQ_set_policy_id(req, policy_id);
    return std::forward<TSRequestBuilder>(*this);
  }

  auto set_nonce(const Asn1Integer&& nonce) -> TSRequestBuilder {
    TS_REQ_set_nonce(req, nonce.as_ptr());
    return std::forward<TSRequestBuilder>(*this);
  }

  auto set_cert_request(bool cert_request) -> TSRequestBuilder {
    TS_REQ_set_cert_req(req, cert_request);
    return std::forward<TSRequestBuilder>(*this);
  }
};

}  // namespace openssl
