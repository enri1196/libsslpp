#pragma once

#include <cstdint>
#include <memory>
#include <ostream>
#include <string_view>
#include <concepts>

#include <openssl/err.h>

#include "expected.hpp"

#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_LIBSSLPP
    #define LIBSSLPP_PUBLIC __declspec(dllexport)
  #else
    #define LIBSSLPP_PUBLIC __declspec(dllimport)
  #endif
#else
  #ifdef BUILDING_LIBSSLPP
    #define LIBSSLPP_PUBLIC __attribute__((visibility ("default")))
  #else
    #define LIBSSLPP_PUBLIC
  #endif
#endif

namespace openssl {

enum class NumFormat : std::uint8_t { Hex, Decimal };

enum class ErrorCode : std::uint8_t {
  AccesError,
  ConversionError,
  IOError,
  ParseError
};

static const auto code_to_string = [](ErrorCode c) -> std::string_view {
  switch (c) {
  case ErrorCode::AccesError:
    return "AccesError";
  case ErrorCode::ConversionError:
    return "ConversionError";
  case ErrorCode::IOError:
    return "IOError";
  case ErrorCode::ParseError:
    return "ParseError";
  }
};

class LIBSSLPP_PUBLIC SSLError {
private:
  ErrorCode code;
  std::string_view what;
public:
  explicit SSLError(const ErrorCode c) : code(c), what(ERR_reason_error_string(ERR_get_error())) {}
  explicit SSLError(const ErrorCode c, const std::string_view&& w) : code(c), what(w) {}

  auto get_code() const -> ErrorCode {
    return code;
  }

  auto get_what() const -> std::string_view {
    return what;
  }

  friend auto operator<<(std::ostream& s, const SSLError& e) -> std::ostream& {
    s << "SSLError: " << code_to_string(e.get_code()) << " " << e.get_what();
    return s;
  }
};

template<class T>
using Expected = tl::expected<T, SSLError>;
using Unexpected = tl::unexpected<SSLError>;

template<class T, class U>
concept IsSSLType = requires (T t, U u) {
  { t.as_ptr() } -> std::constructible_from<T>;
};

/// Error propagation macro to use in conjunction with a funtion which returns
/// an `Expected<T>` object, it automatically unwraps the contained value if any
/// or returns and propagates the error
#define TRY(expr) \
  ({ \
    auto&& temp = expr; \
    if (!temp) [[unlikely]] \
      return Unexpected(temp.error()); \
    std::move(*temp); \
  })

} // namespace openssl
