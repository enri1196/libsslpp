#pragma once

#include <concepts>

#include <openssl/bn.h>

#include "internal/ssl_interface.hpp"
#include "asn1/asn1_integer.hpp"

namespace openssl {

class Asn1Integer;

class BigNum {
private:
  using SSLPtr = std::shared_ptr<BIGNUM>;
  SSLPtr m_ssl_type;

  BigNum();

public:
  BigNum(const BigNum &);
  BigNum(BigNum &&) noexcept;
  auto operator=(const BigNum &) -> BigNum&;
  auto operator=(BigNum &&) noexcept -> BigNum&;
  explicit BigNum(BIGNUM *ptr,
                  std::function<void(BIGNUM *)> free_fn = BN_free);
  ~BigNum();

  auto operator<=>(const BigNum& other) noexcept -> std::strong_ordering;

  auto as_ptr() const noexcept -> BIGNUM*;

  // template<typename Asn1Int>
  // requires std::same_as<Asn1Integer, Asn1Int> && HasAsPtr<Asn1Int>
  static auto from(const Asn1Integer&& asn1_int) -> Expected<BigNum>;

  auto to_string() const -> Expected<std::string_view>;
};

}  // namespace openssl
