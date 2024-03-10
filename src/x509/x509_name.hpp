#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <openssl/x509.h>

#include "../bio.hpp"

namespace openssl::x509 {

static void xname_own_free(X509_NAME *x) { X509_NAME_free(x); }
static void xname_ref_free(X509_NAME *x) {}

class X509NameBuilder;

class X509Name {
private:
  std::shared_ptr<X509_NAME> m_ssl_type;

  X509Name() = delete;
  X509Name(X509_NAME *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &xname_own_free : &xname_ref_free) {}

public:
  static auto own(X509_NAME *ref) -> X509Name { return X509Name(ref); }
  static auto ref(X509_NAME *ref) -> X509Name { return X509Name(ref, false); }

  template <class Builder = X509NameBuilder>
  requires std::is_same_v<Builder, X509NameBuilder>
  static auto init() -> Builder {
    return Builder();
  }

  auto as_ptr() const noexcept -> X509_NAME * { return m_ssl_type.get(); }

  auto to_string() -> std::string {
    auto bio = bio::SSLBio::memory();
    X509_NAME_print_ex(bio.as_ptr(), this->as_ptr(), 0, XN_FLAG_RFC2253);
    return bio.get_mem_ptr();
  }
};

class X509NameEntry {
public:
  enum EEntries {
    C,
    CN,
    DC,
    Email,
    GivenName,
    L,
    O,
    OU,
    SN,
    ST,
    Surname,
    UID,
  };

  constexpr operator EEntries() const { return value; }

  auto to_string() const -> std::string_view {
    std::string_view entry;
    switch (value) {
      case EEntries::C:
        entry = "C";
      case EEntries::CN:
        entry = "CN";
      case EEntries::DC:
        entry = "DC";
      case EEntries::Email:
        entry = "Email";
      case EEntries::GivenName:
        entry = "GivenName";
      case EEntries::L:
        entry = "L";
      case EEntries::O:
        entry = "O";
      case EEntries::OU:
        entry = "OU";
      case EEntries::SN:
        entry = "SN";
      case EEntries::ST:
        entry = "ST";
      case EEntries::Surname:
        entry = "Surname";
      case EEntries::UID:
        entry = "UID";
    }
    return entry;
  }

private:
  EEntries value;
};

class X509NameBuilder {
private:
  X509_NAME* name{X509_NAME_new()};

public:
  auto add_entry(const X509NameEntry&& entry, const std::string_view&& value) -> X509NameBuilder {
    auto field = entry.to_string().data();
    X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, reinterpret_cast<const std::uint8_t*>(value.data()), -1, -1, 0);
    return std::forward<X509NameBuilder>(*this);
  }

  auto build() -> X509Name {
    return X509Name::own(name);
  }
};

} // namespace openssl::x509
