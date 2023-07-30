#include "evp_pkey/base_pkey.hpp"

namespace openssl::key {

BasePKey<Private>::~BasePKey() = default;
BasePKey<Public>::~BasePKey() = default;

}
