module;

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <limits>

#include <openssl/pem.h>

using namespace std;

export module base64;

namespace openssl::base64 {

auto decode(string_view message) -> string {
  if(message.size() > numeric_limits<int>::max())
    return "";

  if(message.empty())
    return "";

  size_t decoded_size =  (((message.length() + 1) * 3) / 4);
  vector<char> message_buffer(decoded_size);

  int length_decoded = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(message_buffer.data()),
                                        reinterpret_cast<const unsigned char*>(message.data()),
                                        static_cast<int32_t>(message.length()));

  if(length_decoded <= 0)
    return "";

  string result(message_buffer.data(), message_buffer.size());
  result.erase(result.find_last_not_of('\0') + 1, string::npos);
  return result;
}

auto base64_encode(string_view message) -> string {
  if(message.size() > numeric_limits<int>::max())
    return "";

  if(message.empty())
    return "";

  size_t encoded_size = (1 + ((message.length() + 2) / 3 * 4));
  vector<char> message_buffer(encoded_size);

  int length_encoded = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(message_buffer.data()),
                                        reinterpret_cast<const unsigned char*>(message.data()),
                                        static_cast<int32_t>(message.length()));

  if(length_encoded <= 0)
    return "";

  string result(message_buffer.data(), message_buffer.size());
  result.erase(result.find_last_not_of('\0') + string::npos);
  return result;
}

}
