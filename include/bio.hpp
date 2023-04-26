#pragma once

#include <filesystem>

#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "internal/ssl_interface.hpp"

namespace openssl {

class LIBSSLPP_PUBLIC SSLBio {
private:
  BIO* m_ssl_type;

  explicit SSLBio(const BIO_METHOD *mtd) : m_ssl_type(BIO_new(mtd)) {}
  explicit SSLBio(BIO *bio) : m_ssl_type(bio) {}

public:
  SSLBio() = delete;
  SSLBio(SSLBio&& bio) noexcept;
  SSLBio(const SSLBio& bio);
  auto operator=(SSLBio&& bio) noexcept -> SSLBio&;
  auto operator=(const SSLBio& bio) -> SSLBio&;
  ~SSLBio();

  static auto init(const BIO_METHOD *mtd = BIO_s_mem()) -> SSLBio;

  static auto open_file(const std::filesystem::path &&path) -> Expected<SSLBio>;

  auto as_ptr() const noexcept -> BIO*;

  auto get_mem_ptr() const -> Expected<std::string_view>;

  auto write_mem(const std::string_view&& buf) -> void;
};  // class SSLBio

} // namespace openssl
