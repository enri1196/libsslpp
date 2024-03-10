module;

#include <string_view>

export module base_ext;

namespace openssl::x509 {

export class BaseX509Ext {
public:
  virtual ~BaseX509Ext() = default;

  virtual constexpr auto oid() const -> std::string_view;
};

}
