module;

#include <memory>
#include <span>

#include <openssl/ts.h>

using namespace std;

export module tsp:tsp_resp;

namespace openssl::ts {

static void tresp_own_free(TS_RESP *x) { TS_RESP_free(x); }
static void tresp_ref_free(TS_RESP *) {}

export class TSResponse {
private:
  shared_ptr<TS_RESP> m_ssl_type;

  TSResponse() = delete;
  TSResponse(TS_RESP *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &tresp_own_free : &tresp_ref_free) {}

public:
  static auto own(TS_RESP *ref) -> TSResponse { return TSResponse(ref); }
  static auto ref(TS_RESP *ref) -> TSResponse { return TSResponse(ref, false); }

  static auto from(span<uint8_t> &&bytes) -> TSResponse {
    const unsigned char *bytes_data = bytes.data();
    auto resp = d2i_TS_RESP(nullptr, &bytes_data, (long)bytes.size());
    if (resp == nullptr) {
      throw runtime_error("TSResponse conversion from bytes Error");
    }
    return {TSResponse(resp)};
  }

  auto as_ptr() const noexcept -> TS_RESP * { return m_ssl_type.get(); }
};

} // namespace openssl::ts
