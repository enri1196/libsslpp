#include "evp_pkey/ec_key.hpp"

namespace openssl::key {

// PUBLIC KEY

EcPublicKey::EcPublicKey(const EcPublicKey&) = default;
EcPublicKey::EcPublicKey(EcPublicKey&&) = default;
EcPublicKey& EcPublicKey::operator=(const EcPublicKey&) = default;
EcPublicKey& EcPublicKey::operator=(EcPublicKey&&) = default;
EcPublicKey::~EcPublicKey() = default;

EcPublicKey::EcPublicKey(EVP_PKEY* oth_key) {
  m_key = oth_key;
};

auto EcPublicKey::as_ptr() const noexcept -> EVP_PKEY* {
  return m_key;
}

auto EcPublicKey::to_string() const -> std::string {
  auto bio = SSLBio();
  PEM_write_bio_PUBKEY(bio.as_ptr(), m_key);
  return bio.get_mem_ptr();
}

// PRIVATE KEY

EcKey::EcKey(const EcKey &) = default;
EcKey::EcKey(EcKey &&) = default;
EcKey &EcKey::operator=(const EcKey &) = default;
EcKey &EcKey::operator=(EcKey &&) = default;
EcKey::~EcKey() { EVP_PKEY_free(m_key); }

EcKey::EcKey(EVP_PKEY* oth_key) {
  m_key = oth_key;
};

EcKey::EcKey(const EcKeyNid nid) {
  m_key = EVP_PKEY_new();
  auto evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY_keygen_init(evp_ctx);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx, (int)nid);
  EVP_PKEY_keygen(evp_ctx, &m_key);
  EVP_PKEY_CTX_free(evp_ctx);
}

auto EcKey::as_ptr() const noexcept -> EVP_PKEY* {
  return m_key;
}

auto EcKey::to_string() const -> std::string {
  auto bio = SSLBio();
  PEM_write_bio_PrivateKey(bio.as_ptr(), this->as_ptr(), nullptr, nullptr, 0, nullptr, nullptr);
  return bio.get_mem_ptr();
}

auto EcKey::get_public() const -> std::unique_ptr<BasePKey<Public>> {
  auto bio = SSLBio();
  auto evp_ptr = this->as_ptr();
  EVP_PKEY_up_ref(this->as_ptr());
  PEM_write_bio_PUBKEY(bio.as_ptr(), evp_ptr);
  auto pub_key = PEM_read_bio_PUBKEY(bio.as_ptr(), &evp_ptr, nullptr, nullptr);
  return std::make_unique<EcPublicKey>(pub_key);
}

auto EcKey::sign(const std::vector<std::uint8_t>& data) const -> std::vector<std::uint8_t> {
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
