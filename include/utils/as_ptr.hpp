#pragma once

#include "internal/ssl_interface.hpp"

template <typename SslPtr>
class LIBSSLPP_PUBLIC AsPtr {
public:
    virtual ~AsPtr() = default;
    virtual auto as_ptr() const -> SslPtr* = 0;
};
