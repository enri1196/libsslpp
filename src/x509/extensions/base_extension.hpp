#pragma once

#include <string_view>

namespace openssl::x509 {

class BaseX509Ext {
public:
  virtual ~BaseX509Ext() = default;

  virtual constexpr auto oid() const -> std::string_view;
};

}
