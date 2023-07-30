#pragma once

#include "internal/ssl_interface.hpp"
#include "utils/to_string.hpp"
#include "utils/as_ptr.hpp"
#include <memory>
#include <vector>

namespace openssl::key {

struct Private {};
struct Public {};

template<typename KeyType>
requires std::same_as<KeyType, Private> || std::same_as<KeyType, Public>
class LIBSSLPP_PUBLIC BasePKey
  : public utils::ToString,
    public AsPtr<EVP_PKEY> {
public:
  virtual ~BasePKey() = default;
};

template <>
class LIBSSLPP_PUBLIC BasePKey<Private>
  : public utils::ToString,
    public AsPtr<EVP_PKEY> {
public:
  virtual ~BasePKey();
  virtual auto get_public() const -> std::unique_ptr<BasePKey<Public>> = 0;
  virtual auto sign(const std::vector<std::uint8_t>& data) const -> std::vector<std::uint8_t> = 0;
};

template <>
class LIBSSLPP_PUBLIC BasePKey<Public>
  : public utils::ToString,
    public AsPtr<EVP_PKEY> {
public:
  virtual ~BasePKey();
};

}
