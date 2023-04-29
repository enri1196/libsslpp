#include "bio.hpp"

namespace openssl {

SSLBio::SSLBio(SSLBio &&bio) noexcept {
  m_ssl_type = bio.m_ssl_type;
  bio.m_ssl_type = nullptr;
}

SSLBio::SSLBio(const SSLBio &bio) {
  BIO_up_ref(bio.as_ptr());
  m_ssl_type = bio.m_ssl_type;
}

auto SSLBio::operator=(SSLBio &&bio) noexcept -> SSLBio & {
  if (this != &bio) {
    m_ssl_type = bio.m_ssl_type;
    bio.m_ssl_type = nullptr;
  }
  return *this;
}

auto SSLBio::operator=(const SSLBio &bio) -> SSLBio & {
  if (this != &bio) {
    BIO_up_ref(bio.as_ptr());
    m_ssl_type = bio.m_ssl_type;
  }
  return *this;
}

SSLBio::~SSLBio() { BIO_free_all(m_ssl_type); }

auto SSLBio::init(const BIO_METHOD *mtd) -> SSLBio { return SSLBio(mtd); }

auto SSLBio::open_file(const std::filesystem::path &&path) -> Expected<SSLBio> {
  auto *bio_ptr = BIO_new_file(path.c_str(), "rb");
  if (bio_ptr == nullptr) {
    return Unexpected(SSLError(ErrorCode::IOError, "File not found"));
  }
  return {SSLBio(bio_ptr)};
}

auto SSLBio::as_ptr() const noexcept -> BIO * { return m_ssl_type; }

auto SSLBio::get_mem_ptr() const -> Expected<std::string_view> {
  BUF_MEM *bptr = BUF_MEM_new();
  // Silence warnings
  // BIO_get_mem_ptr(this->as_ptr(), &bptr);
  BIO_ctrl(this->as_ptr(), 115, 0, reinterpret_cast<char *>(&bptr));
  // BIO_set_close(this->as_ptr(), BIO_NOCLOSE);
  BIO_ctrl(this->as_ptr(), 9, (0x00), nullptr);
  return {{bptr->data, bptr->length}};
}

auto SSLBio::write_mem(const std::string_view &&buf) -> void {
  BIO_write(this->as_ptr(), buf.data(), static_cast<int>(buf.length()));
}

auto SSLBio::write_mem(const std::vector<std::uint8_t> &&buf) -> void {
  BIO_write(this->as_ptr(), buf.data(), static_cast<int>(buf.size()));
}

} // namespace openssl
