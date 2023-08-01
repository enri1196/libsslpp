#pragma once

#include <filesystem>

#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "internal/ssl_interface.hpp"

namespace openssl {

class LIBSSLPP_PUBLIC SSLBio {
private:
  BIO* m_ssl_type;

  SSLBio();
  explicit SSLBio(BIO *bio);

public:
  SSLBio(SSLBio&& bio) noexcept;
  SSLBio(const SSLBio& bio);
  auto operator=(SSLBio&& bio) noexcept -> SSLBio&;
  auto operator=(const SSLBio& bio) -> SSLBio&;
  ~SSLBio();

  static auto open_file(const std::filesystem::path &&path) -> Expected<SSLBio>;

  auto as_ptr() const noexcept -> BIO*;

  auto get_mem_ptr() const -> Expected<std::string>;

  auto write_mem(const std::string_view buf) -> Expected<void>;

  auto write_mem(const std::vector<std::uint8_t> &&buf) -> Expected<void>;
};  // class SSLBio

} // namespace openssl
