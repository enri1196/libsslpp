#include <cstdint>
#include <print>
#include <utility>

import asn1;
import bio;
import evp;
import x509;

using namespace std;
using namespace openssl::asn1;
using namespace openssl::bio;
using namespace openssl::key;
using namespace openssl::x509;

auto main() -> int {
  SSLBio bio = SSLBio::open_file("/workspaces/libsslpp/google.cer");
  X509Certificate cert = X509Certificate::from(std::move(bio));
  println("--- GOOGLE CERT INFO ---");
  println("serial: {}", cert.serial().to_string());
  println("subject: {}", cert.subject().to_string());
  println("issuer: {}", cert.issuer().to_string());
  println("not_before: {}", cert.not_before().to_string());
  println("not_after: {}", cert.not_after().to_string());
  println("pub_key: {}", cert.pub_key().to_string());
  println("extensions: {}", cert.ext_count());
  println("key_usage: {}", cert.key_usage().to_string());
  println("extended_key_usage: {}", cert.extended_key_usage().to_string());

  println("");
  println("--- --- ---");
  println("");

  int64_t serial = 1;
  auto subject = X509NameBuilder::init()
    .add_entry(NameEntry::GivenName, "Enrico")
    .add_entry(NameEntry::Surname, "Rizzo")
    .add_entry(NameEntry::C, "IT")
    .build();
  auto issuer = X509NameBuilder::init()
    .add_entry(NameEntry::OU, "Home")
    .add_entry(NameEntry::CN, "HomeCA")
    .build();
  auto pkey = EvpPKey<Private>::from(EcCurves::X25519);
  auto cert2 = X509CertBuilder::init()
    .set_version(X509Version::V3)
    .set_serial(Asn1Integer::from(serial))
    .set_not_before(Asn1Time::now())
    .set_not_after(Asn1Time::now())
    .set_subject(std::move(subject))
    .set_issuer(std::move(issuer))
    .build(std::move(pkey));
  println("--- CUSTOM CERT INFO ---");
  println("serial: {}", cert2.serial().to_string());
  println("subject: {}", cert2.subject().to_string());
  println("issuer: {}", cert2.issuer().to_string());
  println("not_before: {}", cert2.not_before().to_string());
  println("not_after: {}", cert2.not_after().to_string());
  // println("pub_key: {}", cert2.pub_key().to_string());
  // println("extensions: {}", cert2.ext_count());
  // println("key_usage: {}", cert2.key_usage().to_string());
  // println("extended_key_usage: {}", cert2.extended_key_usage().to_string());
  return 0;
}
