module;

#include <memory>
#include <stdexcept>

#include <openssl/cms.h>

using namespace std;

export module asn1:cms_ci;

import bio;

namespace openssl::asn1 {

static void cmsci_own_free(CMS_ContentInfo *x) { CMS_ContentInfo_free(x); }
static void cmsci_ref_free(CMS_ContentInfo *) {}

export class CmsContentInfo {
private:
  shared_ptr<CMS_ContentInfo> m_ssl_type;

  CmsContentInfo() = delete;
  CmsContentInfo(CMS_ContentInfo *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &cmsci_own_free : &cmsci_ref_free) {}

public:
  static auto own(CMS_ContentInfo *ref) -> CmsContentInfo {
    return CmsContentInfo(ref);
  }
  static auto ref(CMS_ContentInfo *ref) -> CmsContentInfo {
    return CmsContentInfo(ref, false);
  }

  static auto from(bio::SSLBio &&bio) -> CmsContentInfo {
    CMS_ContentInfo *cms = CMS_data_create(bio.as_ptr(), 0);
    if (cms == nullptr) {
      throw runtime_error("CmsContentInfo conversion from BIO Error");
    }
    return CmsContentInfo(cms);
  }
};

}
