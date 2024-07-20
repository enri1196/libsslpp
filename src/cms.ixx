module;

#include <openssl/cms.h>

export module cms;

import asn1;
import bio;
import evp;
import x509;

namespace openssl::cms {

class CMS {
private:

public:
  static auto sign(
      x509::X509Certificate signer,
      key::EvpPKey<key::Private> pkey,
      bio::SSLBio data
  ) -> asn1::CmsContentInfo {
    auto cms = CMS_sign(signer.as_ptr(), pkey.as_ptr(),
                          nullptr, data.as_ptr(), 0);
    return asn1::CmsContentInfo::own(cms);
  }
};

}  // namespace openssl::cms
