module;

export module x509:base_ext;

import :x509_ext;

namespace openssl::x509 {

export class BaseExt {
public:
  virtual auto to_x509_ext() const -> X509Extension = 0;
};

}
