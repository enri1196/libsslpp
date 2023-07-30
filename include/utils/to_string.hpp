#pragma once

#include "internal/ssl_interface.hpp"
#include <string>

namespace openssl::utils {

class LIBSSLPP_PUBLIC ToString {
public:
    virtual auto to_string() const -> std::string = 0;
};

}
