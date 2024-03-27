module;

#include <cstdint>
#include <expected>
#include <string>

#include <openssl/err.h>

using namespace std;

export module error;

namespace openssl::error {

/// Error propagation macro to use in conjunction with a funtion which returns
/// an `expected<T>` object, it automatically unwraps the contained value if any
/// or returns and propagates the error
#define TRY(expr)                                                              \
  ({                                                                           \
    auto &&temp = expr;                                                        \
    if (!temp) [[unlikely]]                                                    \
      return unexpected(SSLError::init());                                     \
    std::move(*temp);                                                          \
  })

export class SSLError {
private:
  uint64_t m_code;
  string m_message;

  SSLError() = default;
  SSLError(uint64_t err_code, string err_msg)
      : m_code(err_code), m_message(err_msg) {}

public:
  static auto init() -> SSLError {
    string curr = ERR_error_string(ERR_get_error(), nullptr);
    return SSLError(ERR_get_error(), curr);
  }

  auto code() const -> uint64_t { return m_code; }

  auto message() const -> string_view { return m_message; }
};

} // namespace openssl::error
