module;

#include <memory>
#include <span>
#include <string>

#include <openssl/bn.h>
#include <openssl/asn1.h>

export module bn;

// import asn1;

namespace openssl::bn {

static void bn_own_free(BIGNUM *x) { BN_free(x); }
static void bn_ref_free(BIGNUM *x) {}

export class BigNum {
private:
  std::shared_ptr<BIGNUM> m_ssl_type;

  BigNum() : m_ssl_type(BN_new(), &bn_own_free) {}
  BigNum(BIGNUM *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &bn_own_free : &bn_ref_free) {}

public:
  static auto own(BIGNUM *ref) -> BigNum { return BigNum(ref); }
  static auto ref(BIGNUM *ref) -> BigNum { return BigNum(ref, false); }

  // Error: Circular dependency :|
  // static auto from(asn1::Asn1Integer&& asn1_int) -> BigNum {
  //   auto bn = ASN1_INTEGER_to_BN(asn1_int.as_ptr(), nullptr);
  //   if (bn == nullptr) {
  //     throw std::runtime_error("BigNum conversion Error");
  //   }
  //   return BigNum(bn);
  // }

  static auto from(std::span<uint8_t> &&bytes) -> BigNum {
    auto bn = BN_bin2bn(bytes.data(), bytes.size(), nullptr);
    if (bn == nullptr) {
      throw std::runtime_error("BigNum conversion from bytes Error");
    }
    return bn;
  }

  auto operator<=>(const BigNum &other) noexcept -> std::strong_ordering {
    switch (BN_cmp(this->as_ptr(), other.as_ptr())) {
    case -1:
      return std::strong_ordering::less;
    case 0:
      return std::strong_ordering::equal;
    case 1:
      return std::strong_ordering::greater;
    default:
      return std::strong_ordering::equal; // shouldn't be reachable
    }
  }

  auto as_ptr() const noexcept -> BIGNUM * { return m_ssl_type.get(); }

  auto to_string() const -> std::string { return BN_bn2dec(this->as_ptr()); }
};

} // namespace openssl::bn
