#include "bio.hpp"
#include "internal/ssl_interface.hpp"
#include "openssl/bio.h"
#include "openssl/buffer.h"
#include "string.h"
#include <cstring>
#include <memory>

namespace openssl {

SSLBio::SSLBio() : m_ssl_type(BIO_new(BIO_s_mem())) {}
SSLBio::SSLBio(BIO *bio) : m_ssl_type(bio) {}
SSLBio::SSLBio(SSLBio&& bio) noexcept = default;
SSLBio::SSLBio(const SSLBio& bio) = default;
auto SSLBio::operator=(SSLBio&& bio) noexcept -> SSLBio& = default;
auto SSLBio::operator=(const SSLBio& bio) -> SSLBio& = default;
SSLBio::~SSLBio() { BIO_free_all(m_ssl_type); };

auto SSLBio::open_file(const std::filesystem::path &&path) -> Expected<SSLBio> {
  auto *bio_ptr = BIO_new_file(path.c_str(), "rb");
  if (bio_ptr == nullptr) {
    return Unexpected(SSLError(ErrorCode::IOError, "File not found"));
  }
  return {SSLBio(bio_ptr)};
}

auto SSLBio::as_ptr() const noexcept -> BIO * { return m_ssl_type; }

auto SSLBio::get_mem_ptr() const -> std::string {
  BUF_MEM *bptr = nullptr;
  BIO_get_mem_ptr(this->as_ptr(), &bptr);
  std::string data(bptr->data, bptr->length);
  return data;
}

auto SSLBio::write_mem(std::string_view buf) -> Expected<void> {
  int result = BIO_write(this->as_ptr(), buf.data(), static_cast<int>(buf.length()));
  if (result == static_cast<int>(buf.length())) {
    return Expected<void>();
  } else {
    return Unexpected(SSLError(ErrorCode::MemoryError));
  }
}

auto SSLBio::write_mem(const std::vector<std::uint8_t> &&buf) -> Expected<void> {
  int result = BIO_write(this->as_ptr(), buf.data(), static_cast<int>(buf.size()));
  if (result == static_cast<int>(buf.size())) {
    return Expected<void>();
  } else {
    return Unexpected(SSLError(ErrorCode::MemoryError));
  }
}

} // namespace openssl
