#pragma once

#include <concepts>

#include <openssl/bn.h>

#include "internal/ssl_interface.hpp"
#include "asn1/asn1_integer.hpp"

namespace openssl {

class Asn1Integer;

class LIBSSLPP_PUBLIC BigNum {
private:
  using FreeFn = decltype([](BIGNUM* ptr){BN_free(ptr);});
  using SSLPtr = std::unique_ptr<BIGNUM, FreeFn>;
  BIGNUM* m_ssl_type;

  BigNum();

public:
  BigNum(const BigNum &) = delete;
  BigNum(BigNum &&) noexcept;
  auto operator=(const BigNum &) -> BigNum& = delete;
  auto operator=(BigNum &&) noexcept -> BigNum&;
  explicit BigNum(BIGNUM *ptr);
  ~BigNum();

  auto operator<=>(const BigNum& other) noexcept -> std::strong_ordering;

  auto as_ptr() const noexcept -> BIGNUM*;

  static auto from(const Asn1Integer&& asn1_int) -> Expected<BigNum>;

  auto to_string() const -> Expected<std::string_view>;
};

}  // namespace openssl
