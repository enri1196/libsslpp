module;

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <limits>

#include <openssl/pem.h>

export module base64;

namespace openssl::base64 {

auto decode(std::string_view message) -> std::string {
  if(message.size() > std::numeric_limits<int>::max())
    return "";

  if(message.empty())
    return "";

  size_t decoded_size =  (((message.length() + 1) * 3) / 4);
  std::vector<uint8_t> message_buffer(decoded_size);

  int length_decoded = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(message_buffer.data()),
                                        reinterpret_cast<const unsigned char*>(message.data()),
                                        message.length());

  if(length_decoded <= 0)
    return "";

  std::string result(message_buffer.data(), message_buffer.size());
  result.erase(result.find_last_not_of('\0') + 1, std::string::npos);
  return result;
}

auto base64_encode(std::string_view message) -> std::string {
  if(message.size() > std::numeric_limits<int>::max())
    return "";

  if(message.empty())
    return "";

  size_t encoded_size = (1 + ((message.length() + 2) / 3 * 4));
  std::vector<uint8_t> message_buffer(encoded_size);

  int length_encoded = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(message_buffer.data()),
                                        reinterpret_cast<const unsigned char*>(message.data()),
                                        message.length());

  if(length_encoded <= 0)
    return "";

  std::string result(message_buffer.data(), message_buffer.size());
  result.erase(result.find_last_not_of('\0') + 1, std::string::npos);
  return result;
}

}
