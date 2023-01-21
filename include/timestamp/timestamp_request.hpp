#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/ts.h>

#include "internal/ssl_interface.hpp"

namespace openssl {

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

  static auto from(const std::vector<std::uint8_t>&& bytes) -> Expected<TSRequest> {
    auto bytes_data = bytes.data();
    auto req = d2i_TS_REQ(nullptr, &bytes_data, bytes.size());
    if (req == nullptr) {
      return Unexpected(SSLError(ErrorCode::ParseError));
    }
    return TSRequest(req);
  }
};

}  // namespace openssl
