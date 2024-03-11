#include <print>
#include <utility>

import bio;
import x509;

using namespace openssl::x509;
using namespace openssl::bio;

auto main() -> int {
  SSLBio bio = SSLBio::open_file("./google.cer");
  X509Certificate cert = X509Certificate::from(std::move(bio));
  std::println("serial: {}", cert.serial().to_string());
  std::println("subject: {}", cert.subject().to_string());
  std::println("issuer: {}", cert.issuer().to_string());
  std::println("not_before: {}", cert.not_before().to_string());
  std::println("not_after: {}", cert.not_after().to_string());
  std::println("pub_key: {}", cert.pub_key().to_string());
  std::println("extensions: {}", cert.ext_count());
  std::println("key_usage: {}", cert.key_usage().to_string());
  std::println("extended_key_usage: {}", cert.extended_key_usage().to_string());
  return 0;
}
