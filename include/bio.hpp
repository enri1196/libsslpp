#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "internal/ssl_interface.hpp"

namespace openssl {

class SSLBio {
private:
  using SSLPtr = std::shared_ptr<BIO>;
  SSLPtr m_ssl_type;

  explicit SSLBio(const BIO_METHOD *mtd) : m_ssl_type(BIO_new(mtd), BIO_free_all) {}

public:
  SSLBio() = delete;
  SSLBio(SSLBio &&) noexcept = default;
  SSLBio(const SSLBio &) = default;
  auto operator=(SSLBio &&) noexcept -> SSLBio & = default;
  auto operator=(const SSLBio &) -> SSLBio & = default;
  explicit SSLBio(BIO *ptr,
                  std::function<void(BIO *)> free_fn = BIO_free_all)
      : m_ssl_type(ptr, free_fn) {}
  ~SSLBio() = default;

  static auto init(const BIO_METHOD *mtd = BIO_s_mem()) -> SSLBio {
    return SSLBio(mtd);
  }

  static auto open_file(const std::filesystem::path &&path) -> Expected<SSLBio> {
    auto *bio_ptr = BIO_new_file(path.c_str(), "rb");
    if (bio_ptr == nullptr) {
      return Unexpected(SSLError(ErrorCode::IOError, "File not found"));
    }
    return {SSLBio(bio_ptr)};
  }

  auto as_ptr() const noexcept -> BIO* { return m_ssl_type.get(); }

  auto get_mem_ptr() -> Expected<std::string_view> {
    BUF_MEM *bptr = BUF_MEM_new();
    BIO_get_mem_ptr(this->as_ptr(), &bptr);
    BIO_set_close(this->as_ptr(), BIO_NOCLOSE);
    return {{bptr->data, bptr->length}};
  }
};  // class SSLBio

} // namespace openssl
