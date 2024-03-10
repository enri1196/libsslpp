#pragma once

#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

#include <openssl/bio.h>
#include <openssl/buffer.h>

namespace openssl::bio {

static void bio_own_free(BIO *x) { BIO_free_all(x); }
static void bio_ref_free(BIO *x) {}

class SSLBio {
private:
  std::shared_ptr<BIO> m_ssl_type;

  SSLBio() : m_ssl_type(BIO_new(BIO_s_mem()), &bio_own_free) {}
  explicit SSLBio(BIO *bio, bool take_ownership = true)
      : m_ssl_type(bio, take_ownership ? &bio_own_free : &bio_ref_free) {}

public:
  static auto own(BIO *ref) -> SSLBio { return SSLBio(ref); }
  static auto ref(BIO *ref) -> SSLBio { return SSLBio(ref, false); }

  static auto memory() -> SSLBio { return SSLBio(); }

  static auto open_file(const std::filesystem::path &path) -> SSLBio {
    auto *bio_ptr = BIO_new_file(path.c_str(), "rb");
    if (bio_ptr == nullptr) {
      // return Unexpected(SSLError(ErrorCode::IOError, "File not found"));
      throw std::runtime_error("File Not Found");
    }
    return SSLBio(bio_ptr);
  }

  auto as_ptr() const noexcept -> BIO * { return m_ssl_type.get(); }

  auto get_mem_ptr() const -> std::string {
    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(this->as_ptr(), &bptr);
    BIO_set_close(this->as_ptr(), BIO_NOCLOSE);
    if (bptr == nullptr) {
      throw std::runtime_error("BIO Error MemPtr");
    }
    return std::string(bptr->data, bptr->length);
  }

  auto write_mem(std::string_view &&buf) -> void {
    int result =
        BIO_write(this->as_ptr(), buf.data(), static_cast<int>(buf.length()));
    if (result < static_cast<int>(buf.length())) {
      throw std::runtime_error("Mem Write Error");
    }
  }

  auto write_mem(std::span<std::uint8_t> &&buf) -> void {
    int result =
        BIO_write(this->as_ptr(), buf.data(), static_cast<int>(buf.size()));
    if (result < static_cast<int>(buf.size())) {
      throw std::runtime_error("Mem Write Error");
    }
  }

}; // class SSLBio

} // namespace openssl::bio
