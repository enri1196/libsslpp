#pragma once

#include <memory>
#include <string>
#include <type_traits>

#include <openssl/buffer.h>

#include "openssl/ossl_typ.h"
#include "internal/ssl_interface.hpp"

namespace openssl {

class SSLBio;

class LIBSSLPP_PUBLIC BufMem {
private:
  using SSLPtr = std::shared_ptr<BUF_MEM>;
  SSLPtr m_ssl_type;

  BufMem() : m_ssl_type(BUF_MEM_new(), BUF_MEM_free) {}

public:
  BufMem(BufMem&&) noexcept = default;
  BufMem(const BufMem&) = default;
  auto operator=(BufMem&&) noexcept -> BufMem& = default;
  auto operator=(const BufMem&) -> BufMem& = default;
  explicit BufMem(BUF_MEM* ptr) : m_ssl_type(ptr, BUF_MEM_free) {}
  ~BufMem();

  static auto init() -> BufMem {
    return BufMem(BUF_MEM_new());
  }

  auto as_ptr() const noexcept -> BUF_MEM * { return m_ssl_type.get(); }

  template <class BIOClass>
  requires std::is_same_v<BIOClass, SSLBio>
  static auto from_bio(const BIOClass &&bio) -> Expected<BufMem> {
    auto buf = BufMem();
    const int cmd = 115;
    auto *buf_ptr = reinterpret_cast<char *>(buf.as_ptr());
    if (BIO_ctrl(bio.as_ptr(), cmd, 0, buf_ptr) == 0) {
      return Unexpected(SSLError(ErrorCode::IOError));
    }
    return {std::move(buf)};
  }

  auto len() const -> std::size_t { return this->as_ptr()->length; }

  auto to_string() const -> std::string_view {
    return {this->as_ptr()->data, this->as_ptr()->length};
  }
};  // class BufMem

} // namespace openssl
