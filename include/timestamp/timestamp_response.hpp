#pragma once

#include <vector>

#include <openssl/ts.h>

#include "internal/ssl_interface.hpp"

namespace openssl {

class TSResponse {
private:
  using SSLPtr = std::shared_ptr<TS_RESP>;
  SSLPtr m_ssl_type;

  TSResponse() : m_ssl_type(TS_RESP_new(), TS_RESP_free) {}

public:
  TSResponse(const TSResponse &) = default;
  TSResponse(TSResponse &&) noexcept = default;
  auto operator=(const TSResponse &) -> TSResponse & = default;
  auto operator=(TSResponse &&) noexcept -> TSResponse & = default;
  explicit TSResponse(TS_RESP *ptr,
                       std::function<void(TS_RESP *)> free_fn = TS_RESP_free)
      : m_ssl_type(ptr, free_fn) {}
  ~TSResponse() = default;

  auto as_ptr() const noexcept -> TS_RESP* { return m_ssl_type.get(); }

  static auto from(const std::vector<std::uint8_t>&& bytes) -> Expected<TSResponse> {
    auto bytes_data = bytes.data();
    auto req = d2i_TS_RESP(nullptr, &bytes_data, bytes.size());
    if (req == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return TSResponse(req);
  }
};

}  // namespace openssl
