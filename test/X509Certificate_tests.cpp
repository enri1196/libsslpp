#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

#include "gtest/gtest.h"

#include "x509_certificate.hpp"

constexpr std::string_view PEM_CERT =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIOHDCCDQSgAwIBAgIRAOslSi6LureTCv/SK9zpGK4wDQYJKoZIhvcNAQELBQAw"
    "RjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM"
    "TEMxEzARBgNVBAMTCkdUUyBDQSAxQzMwHhcNMjIxMTI4MDgxNzExWhcNMjMwMjIw"
    "MDgxNzEwWjAXMRUwEwYDVQQDDAwqLmdvb2dsZS5jb20wWTATBgcqhkjOPQIBBggq"
    "hkjOPQMBBwNCAARkHyEOMNI6QsnKMgYD5lwZSyU35HW4nUW2QJkl3oRpsgptRCEK"
    "R/HD+2ylv7ojjdde4tVBBBzr7HhSk1G7vJ4xo4IL/TCCC/kwDgYDVR0PAQH/BAQD"
    "AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE"
    "FIuBlDMcv14arlOLfHnxbrohZtM2MB8GA1UdIwQYMBaAFIp0f6+Fze6VzT2c0OJG"
    "FPNxNR0nMGoGCCsGAQUFBwEBBF4wXDAnBggrBgEFBQcwAYYbaHR0cDovL29jc3Au"
    "cGtpLmdvb2cvZ3RzMWMzMDEGCCsGAQUFBzAChiVodHRwOi8vcGtpLmdvb2cvcmVw"
    "by9jZXJ0cy9ndHMxYzMuZGVyMIIJrQYDVR0RBIIJpDCCCaCCDCouZ29vZ2xlLmNv"
    "bYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNvbYIJKi5iZG4uZGV2ghUqLm9yaWdpbi10"
    "ZXN0LmJkbi5kZXaCEiouY2xvdWQuZ29vZ2xlLmNvbYIYKi5jcm93ZHNvdXJjZS5n"
    "b29nbGUuY29tghgqLmRhdGFjb21wdXRlLmdvb2dsZS5jb22CCyouZ29vZ2xlLmNh"
    "ggsqLmdvb2dsZS5jbIIOKi5nb29nbGUuY28uaW6CDiouZ29vZ2xlLmNvLmpwgg4q"
    "Lmdvb2dsZS5jby51a4IPKi5nb29nbGUuY29tLmFygg8qLmdvb2dsZS5jb20uYXWC"
    "DyouZ29vZ2xlLmNvbS5icoIPKi5nb29nbGUuY29tLmNvgg8qLmdvb2dsZS5jb20u"
    "bXiCDyouZ29vZ2xlLmNvbS50coIPKi5nb29nbGUuY29tLnZuggsqLmdvb2dsZS5k"
    "ZYILKi5nb29nbGUuZXOCCyouZ29vZ2xlLmZyggsqLmdvb2dsZS5odYILKi5nb29n"
    "bGUuaXSCCyouZ29vZ2xlLm5sggsqLmdvb2dsZS5wbIILKi5nb29nbGUucHSCEiou"
    "Z29vZ2xlYWRhcGlzLmNvbYIPKi5nb29nbGVhcGlzLmNughEqLmdvb2dsZXZpZGVv"
    "LmNvbYIMKi5nc3RhdGljLmNughAqLmdzdGF0aWMtY24uY29tgg9nb29nbGVjbmFw"
    "cHMuY26CESouZ29vZ2xlY25hcHBzLmNughFnb29nbGVhcHBzLWNuLmNvbYITKi5n"
    "b29nbGVhcHBzLWNuLmNvbYIMZ2tlY25hcHBzLmNugg4qLmdrZWNuYXBwcy5jboIS"
    "Z29vZ2xlZG93bmxvYWRzLmNughQqLmdvb2dsZWRvd25sb2Fkcy5jboIQcmVjYXB0"
    "Y2hhLm5ldC5jboISKi5yZWNhcHRjaGEubmV0LmNughByZWNhcHRjaGEtY24ubmV0"
    "ghIqLnJlY2FwdGNoYS1jbi5uZXSCC3dpZGV2aW5lLmNugg0qLndpZGV2aW5lLmNu"
    "ghFhbXBwcm9qZWN0Lm9yZy5jboITKi5hbXBwcm9qZWN0Lm9yZy5jboIRYW1wcHJv"
    "amVjdC5uZXQuY26CEyouYW1wcHJvamVjdC5uZXQuY26CF2dvb2dsZS1hbmFseXRp"
    "Y3MtY24uY29tghkqLmdvb2dsZS1hbmFseXRpY3MtY24uY29tghdnb29nbGVhZHNl"
    "cnZpY2VzLWNuLmNvbYIZKi5nb29nbGVhZHNlcnZpY2VzLWNuLmNvbYIRZ29vZ2xl"
    "dmFkcy1jbi5jb22CEyouZ29vZ2xldmFkcy1jbi5jb22CEWdvb2dsZWFwaXMtY24u"
    "Y29tghMqLmdvb2dsZWFwaXMtY24uY29tghVnb29nbGVvcHRpbWl6ZS1jbi5jb22C"
    "FyouZ29vZ2xlb3B0aW1pemUtY24uY29tghJkb3VibGVjbGljay1jbi5uZXSCFCou"
    "ZG91YmxlY2xpY2stY24ubmV0ghgqLmZscy5kb3VibGVjbGljay1jbi5uZXSCFiou"
    "Zy5kb3VibGVjbGljay1jbi5uZXSCDmRvdWJsZWNsaWNrLmNughAqLmRvdWJsZWNs"
    "aWNrLmNughQqLmZscy5kb3VibGVjbGljay5jboISKi5nLmRvdWJsZWNsaWNrLmNu"
    "ghFkYXJ0c2VhcmNoLWNuLm5ldIITKi5kYXJ0c2VhcmNoLWNuLm5ldIIdZ29vZ2xl"
    "dHJhdmVsYWRzZXJ2aWNlcy1jbi5jb22CHyouZ29vZ2xldHJhdmVsYWRzZXJ2aWNl"
    "cy1jbi5jb22CGGdvb2dsZXRhZ3NlcnZpY2VzLWNuLmNvbYIaKi5nb29nbGV0YWdz"
    "ZXJ2aWNlcy1jbi5jb22CF2dvb2dsZXRhZ21hbmFnZXItY24uY29tghkqLmdvb2ds"
    "ZXRhZ21hbmFnZXItY24uY29tghhnb29nbGVzeW5kaWNhdGlvbi1jbi5jb22CGiou"
    "Z29vZ2xlc3luZGljYXRpb24tY24uY29tgiQqLnNhZmVmcmFtZS5nb29nbGVzeW5k"
    "aWNhdGlvbi1jbi5jb22CFmFwcC1tZWFzdXJlbWVudC1jbi5jb22CGCouYXBwLW1l"
    "YXN1cmVtZW50LWNuLmNvbYILZ3Z0MS1jbi5jb22CDSouZ3Z0MS1jbi5jb22CC2d2"
    "dDItY24uY29tgg0qLmd2dDItY24uY29tggsybWRuLWNuLm5ldIINKi4ybWRuLWNu"
    "Lm5ldIIUZ29vZ2xlZmxpZ2h0cy1jbi5uZXSCFiouZ29vZ2xlZmxpZ2h0cy1jbi5u"
    "ZXSCDGFkbW9iLWNuLmNvbYIOKi5hZG1vYi1jbi5jb22CFGdvb2dsZXNhbmRib3gt"
    "Y24uY29tghYqLmdvb2dsZXNhbmRib3gtY24uY29tgg0qLmdzdGF0aWMuY29tghQq"
    "Lm1ldHJpYy5nc3RhdGljLmNvbYIKKi5ndnQxLmNvbYIRKi5nY3BjZG4uZ3Z0MS5j"
    "b22CCiouZ3Z0Mi5jb22CDiouZ2NwLmd2dDIuY29tghAqLnVybC5nb29nbGUuY29t"
    "ghYqLnlvdXR1YmUtbm9jb29raWUuY29tggsqLnl0aW1nLmNvbYILYW5kcm9pZC5j"
    "b22CDSouYW5kcm9pZC5jb22CEyouZmxhc2guYW5kcm9pZC5jb22CBGcuY26CBiou"
    "Zy5jboIEZy5jb4IGKi5nLmNvggZnb28uZ2yCCnd3dy5nb28uZ2yCFGdvb2dsZS1h"
    "bmFseXRpY3MuY29tghYqLmdvb2dsZS1hbmFseXRpY3MuY29tggpnb29nbGUuY29t"
    "ghJnb29nbGVjb21tZXJjZS5jb22CFCouZ29vZ2xlY29tbWVyY2UuY29tgghnZ3Bo"
    "dC5jboIKKi5nZ3BodC5jboIKdXJjaGluLmNvbYIMKi51cmNoaW4uY29tggh5b3V0"
    "dS5iZYILeW91dHViZS5jb22CDSoueW91dHViZS5jb22CFHlvdXR1YmVlZHVjYXRp"
    "b24uY29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tgg95b3V0dWJla2lkcy5jb22C"
    "ESoueW91dHViZWtpZHMuY29tggV5dC5iZYIHKi55dC5iZYIaYW5kcm9pZC5jbGll"
    "bnRzLmdvb2dsZS5jb22CG2RldmVsb3Blci5hbmRyb2lkLmdvb2dsZS5jboIcZGV2"
    "ZWxvcGVycy5hbmRyb2lkLmdvb2dsZS5jboIYc291cmNlLmFuZHJvaWQuZ29vZ2xl"
    "LmNuMCEGA1UdIAQaMBgwCAYGZ4EMAQIBMAwGCisGAQQB1nkCBQMwPAYDVR0fBDUw"
    "MzAxoC+gLYYraHR0cDovL2NybHMucGtpLmdvb2cvZ3RzMWMzL2ZWSnhiVi1LdG1r"
    "LmNybDCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB3ALc++yTfnE26dfI5xbpY9Gxd"
    "/ELPep81xJ4dCYEl7bSZAAABhL2HJawAAAQDAEgwRgIhAKUdwRyhhzG5kGmBGUU5"
    "hfywBD9sAAH65R2rnHU7A+6MAiEAglChp53Cacbjtw4/dkE1VYXTecPjWhHGvJih"
    "oKii0VgAdQDoPtDaPvUGNTLnVyi8iWvJA9PL0RFr7Otp4Xd9bQa9bgAAAYS9hyWd"
    "AAAEAwBGMEQCIDa23V/2uha2UvFaazMFw8FxcirACnZJQfQiCgWMX7DoAiAYL8ZK"
    "a1XA+kfV7MqLMFUWVnc4VEGWfarsfriPJCazfjANBgkqhkiG9w0BAQsFAAOCAQEA"
    "2dndBsFhggTgfKisJEURN+bMhesXc+hIjJLz2OgX6IdeVXKIFhdGc7c38mU6Ahh4"
    "pUgwrh6ZCZtmGzbYSMzDMJ9WZe38rd3+qzK597h3IvfCSbw04KTw7D/z/4b+QSDX"
    "/d2de0dWIGlovjcAc74L3PkeITFppg0p6P2gfIrCHj1eQlXaRrEwrSZEvRvN0vr4"
    "lPCrVRK3PkHbMh5rJMyl11uWEfpZAnAQ+I0g6HN3Fd2GQJUgKePGVwX9l9hlYy6O"
    "9Y75EAGlBaVuecvYMM4V5JlgYSElJhiz27Lln9o+sXluYKHrMFLsjYk4I2O/j2H/"
    "NWmfhcT58VtdBWjDOegaQA==\n"
    "-----END CERTIFICATE-----";

TEST(X509Certificate, parse_from_file) {
  const auto pem_cert =
    openssl::X509Certificate::parse(
      std::filesystem::path("test/test_files/google.cer"));
  if (!pem_cert.has_value()) {
    std::cout << pem_cert.error() << "\n";
    FAIL();
  }
  EXPECT_EQ(pem_cert.has_value(), true);
}

TEST(X509Certificate, parse_from_bytes) {
  const std::vector<std::uint8_t> vec(PEM_CERT.begin(), PEM_CERT.end());
  const auto pem_cert =
      openssl::X509Certificate::parse(std::move(vec));
  if (!pem_cert.has_value()) {
    std::cout << pem_cert.error() << "\n";
    FAIL();
  }
  EXPECT_EQ(pem_cert.has_value(), true);
}

TEST(X509Certificate, parse_from_string) {
  const auto pem_cert =
      openssl::X509Certificate::parse(std::string_view(PEM_CERT));
  if (!pem_cert.has_value()) {
    std::cout << pem_cert.error() << "\n";
    FAIL();
  }
  EXPECT_EQ(pem_cert.has_value(), true);
}

TEST(X509Certificate, parse_error) {
  const std::vector<std::uint8_t> vec{};
  const auto pem_cert =
      openssl::X509Certificate::parse(std::move(vec));
  if (pem_cert.has_value()) {
    std::cout << pem_cert.error() << "\n";
    FAIL();
  }
  EXPECT_EQ(pem_cert.has_value(), false);
}

TEST(X509Certificate, print_certificate) {
  const auto pem_cert =
      openssl::X509Certificate::parse(std::string_view(PEM_CERT));
  if (!pem_cert.has_value()) {
    std::cout << pem_cert.error() << "\n";
    FAIL();
  }
  // std::cout << pem_cert->to_string().value() << "\n";
  const auto cert_str = pem_cert->to_string();
  EXPECT_EQ(cert_str.has_value(), true);
}

TEST(X509Certificate, get_not_before) {
  const auto pem_cert =
      openssl::X509Certificate::parse(std::string_view(PEM_CERT));
  if (!pem_cert.has_value()) {
    std::cout << pem_cert.error() << "\n";
    FAIL();
  }
  const auto date = pem_cert->not_before()->to_string().value();
  const auto expected_date = "Nov 28 08:17:11 2022 GMT";
  std::cout << date << "\n";
  EXPECT_EQ(date, expected_date);
}

TEST(X509Certificate, get_not_after) {
  const auto pem_cert =
      openssl::X509Certificate::parse(std::string_view(PEM_CERT));
  if (!pem_cert.has_value()) {
    std::cout << pem_cert.error() << "\n";
    FAIL();
  }
  const auto date = pem_cert->not_after()->to_string().value();
  const auto expected_date = "Feb 20 08:17:10 2023 GMT";
  std::cout << date << "\n";
  EXPECT_EQ(date, expected_date);
}
