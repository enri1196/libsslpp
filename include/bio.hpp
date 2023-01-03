#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>

#include <openssl/bio.h>

#include "buffer.hpp"
#include "internal/ssl_interface.hpp"

namespace openssl {

class LIBSSLPP_PUBLIC SSLBio {
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
  explicit SSLBio(BIO *ptr) : m_ssl_type(ptr, BIO_free_all) {}
  ~SSLBio();

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

  /// Returns the internal buffer of the BIO structure, it doesn't need to
  /// be freed, access to the internal fields is public by default:
  /// ```c++
  /// auto b = bio.get_buffer();
  /// do_smoething(b->data, b->length);
  /// b->data     // do something
  /// b->length   // do something
  /// ```
  auto get_buffer() -> Expected<BufMem> {
    return BufMem::from_bio(std::move(*this));
  }

  auto get_mem_data() -> Expected<std::string_view> {
    char* buffer{};
    // BIO_get_mem_data
    std::int64_t length = BIO_ctrl(this->as_ptr(), 3, 0, &buffer);
    if (length < 0) {
      return Unexpected(ErrorCode::ConversionError);
    }
    return {{buffer, static_cast<std::size_t>(length)}};
  }
};  // class SSLBio

} // namespace openssl
