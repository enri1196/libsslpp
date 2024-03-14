module;

#include <memory>
#include <string>
#include <string_view>

#include <openssl/x509.h>

using namespace std;

export module x509:x509_name;

import bio;

namespace openssl::x509 {

static void xname_own_free(X509_NAME *x) { X509_NAME_free(x); }
static void xname_ref_free(X509_NAME *) {}

export class X509NameBuilder;

export class X509Name {
private:
  shared_ptr<X509_NAME> m_ssl_type;

  X509Name() = delete;
  X509Name(X509_NAME *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &xname_own_free : &xname_ref_free) {}

public:
  static auto own(X509_NAME *ref) -> X509Name { return X509Name(ref); }
  static auto ref(X509_NAME *ref) -> X509Name { return X509Name(ref, false); }

  template <class Builder = X509NameBuilder>
  requires is_same_v<Builder, X509NameBuilder>
  static auto init() -> Builder {
    return Builder();
  }

  auto as_ptr() const noexcept -> X509_NAME * { return m_ssl_type.get(); }

  auto to_string() -> string {
    auto bio = bio::SSLBio::memory();
    X509_NAME_print_ex(bio.as_ptr(), this->as_ptr(), 0, XN_FLAG_RFC2253);
    return bio.get_mem_ptr();
  }
};

export class X509NameEntry {
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

  auto to_string() const -> string_view {
    string_view entry;
    switch (value) {
      case EEntries::C:
        entry = "C";
        break;
      case EEntries::CN:
        entry = "CN";
        break;
      case EEntries::DC:
        entry = "DC";
        break;
      case EEntries::Email:
        entry = "Email";
        break;
      case EEntries::GivenName:
        entry = "GivenName";
        break;
      case EEntries::L:
        entry = "L";
        break;
      case EEntries::O:
        entry = "O";
        break;
      case EEntries::OU:
        entry = "OU";
        break;
      case EEntries::SN:
        entry = "SN";
        break;
      case EEntries::ST:
        entry = "ST";
        break;
      case EEntries::Surname:
        entry = "Surname";
        break;
      case EEntries::UID:
        entry = "UID";
        break;
    }
    return entry;
  }

private:
  EEntries value;
};

export class X509NameBuilder {
private:
  X509_NAME* name{X509_NAME_new()};

public:
  auto add_entry(const X509NameEntry&& entry, string_view &&value) -> X509NameBuilder {
    auto field = entry.to_string().data();
    X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, reinterpret_cast<const uint8_t*>(value.data()), -1, -1, 0);
    return std::forward<X509NameBuilder>(*this);
  }

  auto build() -> X509Name {
    return X509Name::own(name);
  }
};

} // namespace openssl::x509
