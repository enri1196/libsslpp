#include "gtest/gtest.h"
#include <iostream>

#include "x509/x509_name.hpp"

TEST(X509Name, print_name) {
  using namespace openssl;
  auto name = X509Name::init()
    .add_entry(X509NameEntry(X509NameEntry::entries::CN), "Common Name")
    .add_entry(X509NameEntry(X509NameEntry::entries::O), "Organization")
    .add_entry(X509NameEntry(X509NameEntry::entries::C), "IT")
    .build();

  auto name_str = name.to_string().value();
  std::cout << name_str << "\n";
  EXPECT_FALSE(name_str.empty());
  EXPECT_EQ("C=IT,O=Organization,CN=Common Name", name_str);
}
