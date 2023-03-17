#include <optional>
#include <stdexcept>
#include <utility>

#include "internal/ssl_interface.hpp"

namespace openssl {

template <typename T>
class Stack {
private:
  std::vector<std::optional<T>> stack_data;

public:
  void push(const T &value) { stack_data.emplace_back(value); }

  void push(T &&value) { stack_data.emplace_back(std::move(value)); }

  Expected<std::optional<T&>> top() {
    if (stack_data.empty()) {
      return Unexpected(SSLError(ErrorCode::OutOfRange));
    }
    return stack_data.back();
  }

  Expected<std::optional<const T&>> top() const {
    if (stack_data.empty()) {
      return Unexpected(SSLError(ErrorCode::OutOfRange));
    }
    return stack_data.back();
  }

  std::optional<T> pop() {
    if (stack_data.empty()) {
      return std::nullopt;
    }
    T value = std::move(stack_data.back());
    stack_data.pop_back();
    return value;
  }

  bool empty() const { return stack_data.empty(); }

  size_t size() const { return stack_data.size(); }
};

}
