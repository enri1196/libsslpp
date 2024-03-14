#include <print>
#include <utility>

import bio;
import x509;

using namespace std;
using namespace openssl::x509;
using namespace openssl::bio;

auto main() -> int {
  SSLBio bio = SSLBio::open_file("/workspaces/libsslpp/google.cer");
  X509Certificate cert = X509Certificate::from(std::move(bio));
  println("serial: {}", cert.serial().to_string());
  println("subject: {}", cert.subject().to_string());
  println("issuer: {}", cert.issuer().to_string());
  println("not_before: {}", cert.not_before().to_string());
  println("not_after: {}", cert.not_after().to_string());
  println("pub_key: {}", cert.pub_key().to_string());
  println("extensions: {}", cert.ext_count());
  println("key_usage: {}", cert.key_usage().to_string());
  println("extended_key_usage: {}", cert.extended_key_usage().to_string());
  return 0;
}
