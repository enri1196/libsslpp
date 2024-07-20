module;

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <limits>

#include <openssl/pem.h>

export module base64;

using namespace std;

namespace openssl::base64 {

auto decode(string_view message) -> vector<uint8_t> {
  if (message.size() > numeric_limits<int>::max() || message.empty())
    return {};

  size_t decoded_size = (((message.length() + 1) * 3) / 4);
  vector<uint8_t> message_buffer(decoded_size);

  int32_t length_decoded = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(message_buffer.data()),
                                        reinterpret_cast<const unsigned char*>(message.data()),
                                        static_cast<int32_t>(message.length()));

  if (length_decoded <= 0)
    return {};

  return message_buffer;
}

auto encode(span<uint8_t> message) -> string {
  if (message.size() > numeric_limits<int>::max() || message.empty())
    return "";

  size_t encoded_size = (1 + ((message.size() + 2) / 3 * 4));
  vector<char> message_buffer(encoded_size);

  int32_t length_encoded = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(message_buffer.data()),
                                        reinterpret_cast<const unsigned char*>(message.data()),
                                        static_cast<int32_t>(message.size()));

  if (length_encoded <= 0)
    return "";

  string result(message_buffer.data(), message_buffer.size());
  return result;
}

}  // namespace openssl::base64
