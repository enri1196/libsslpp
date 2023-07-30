#include "evp_pkey/rsa_key.hpp"

namespace openssl::key {

// PUBLIC KEY

RsaPublicKey::RsaPublicKey(const RsaPublicKey&) = default;
RsaPublicKey::RsaPublicKey(RsaPublicKey&&) = default;
RsaPublicKey& RsaPublicKey::operator=(const RsaPublicKey&) = default;
RsaPublicKey& RsaPublicKey::operator=(RsaPublicKey&&) = default;
RsaPublicKey::~RsaPublicKey() = default;

RsaPublicKey::RsaPublicKey(EVP_PKEY* oth_key) {
  m_key = oth_key;
};

auto RsaPublicKey::as_ptr() const noexcept -> EVP_PKEY* {
  return m_key;
}

auto RsaPublicKey::to_string() const -> std::string {
  auto bio = SSLBio();
  PEM_write_bio_PUBKEY(bio.as_ptr(), m_key);
  return bio.get_mem_ptr();
}

// PRIVATE KEY

RsaKey::RsaKey(const RsaKey &) = default;
RsaKey::RsaKey(RsaKey &&) = default;
RsaKey &RsaKey::operator=(const RsaKey &) = default;
RsaKey &RsaKey::operator=(RsaKey &&) = default;
RsaKey::~RsaKey() { EVP_PKEY_free(m_key); }

RsaKey::RsaKey(EVP_PKEY* oth_key) {
  m_key = oth_key;
};

RsaKey::RsaKey(const RsaKeyBits bits) {
  m_key = EVP_PKEY_new();
  auto evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(evp_ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx, 2048);
  EVP_PKEY_keygen(evp_ctx, &m_key);
  EVP_PKEY_CTX_free(evp_ctx);
}

auto RsaKey::as_ptr() const noexcept -> EVP_PKEY* {
  return m_key;
}

auto RsaKey::to_string() const -> std::string {
  auto bio = SSLBio();
  PEM_write_bio_PrivateKey(bio.as_ptr(), this->as_ptr(), nullptr, nullptr, 0, nullptr, nullptr);
  return bio.get_mem_ptr();
}

auto RsaKey::get_public() const -> std::unique_ptr<BasePKey<Public>> {
  auto bio = SSLBio();
  auto evp_ptr = this->as_ptr();
  EVP_PKEY_up_ref(this->as_ptr());
  PEM_write_bio_PUBKEY(bio.as_ptr(), evp_ptr);
  auto pub_key = PEM_read_bio_PUBKEY(bio.as_ptr(), &evp_ptr, nullptr, nullptr);
  return std::make_unique<RsaPublicKey>(pub_key);
}

auto RsaKey::sign(const std::vector<std::uint8_t>& data) const -> std::vector<std::uint8_t> {
  auto ctx = EVP_PKEY_CTX_new(this->as_ptr(), nullptr);
  EVP_PKEY_sign_init(ctx);
  std::size_t sig_len = 0;
  EVP_PKEY_sign(ctx, nullptr, &sig_len, data.data(), data.size());
  auto sig_data = std::vector<std::uint8_t>(sig_len);
  EVP_PKEY_sign(ctx, sig_data.data(), &sig_len, data.data(), data.size());
  EVP_PKEY_CTX_free(ctx);
  return sig_data;
}

}
