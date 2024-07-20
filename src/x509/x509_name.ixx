module;

#include <print>
#include <memory>
#include <string>
#include <string_view>
#include <stdexcept>

#include <openssl/x509.h>

export module x509:x509_name;
import bio;

using namespace std;


namespace openssl::x509 {

static void xname_own_free(X509_NAME *x) { X509_NAME_free(x); }
static void xname_ref_free(X509_NAME *) {}

export class X509Name {
private:
  shared_ptr<X509_NAME> m_ssl_type;

  X509Name() = delete;
  X509Name(X509_NAME *ref, bool take_ownership = true)
      : m_ssl_type(ref, take_ownership ? &xname_own_free : &xname_ref_free) {}

public:
  static auto own(X509_NAME *ref) -> X509Name { return X509Name(ref); }
  static auto ref(X509_NAME *ref) -> X509Name { return X509Name(ref, false); }

  auto as_ptr() const noexcept -> X509_NAME * { return m_ssl_type.get(); }

  auto to_string() -> string {
    auto bio = bio::SSLBio::memory();
    X509_NAME_print_ex(bio.as_ptr(), this->as_ptr(), 0, XN_FLAG_RFC2253);
    return bio.get_mem_ptr();
  }
};

export enum class NameEntry {
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

export class X509NameEntry {
private:
  NameEntry value;

  X509NameEntry() = default;

public:
  static auto from(NameEntry entry) -> X509NameEntry {
    auto ent = X509NameEntry();
    ent.value = entry;
    return ent;
  }

  auto to_string() const -> string_view {
    string_view entry;
    switch (value) {
      case NameEntry::C:
        entry = "C";
        break;
      case NameEntry::CN:
        entry = "CN";
        break;
      case NameEntry::DC:
        entry = "DC";
        break;
      case NameEntry::Email:
        entry = "Email";
        break;
      case NameEntry::GivenName:
        entry = "GN";
        break;
      case NameEntry::L:
        entry = "L";
        break;
      case NameEntry::O:
        entry = "O";
        break;
      case NameEntry::OU:
        entry = "OU";
        break;
      case NameEntry::SN:
        entry = "SN";
        break;
      case NameEntry::ST:
        entry = "ST";
        break;
      case NameEntry::Surname:
        entry = "SN";
        break;
      case NameEntry::UID:
        entry = "UID";
        break;
    }
    return entry;
  }
};

export class X509NameBuilder {
private:
  X509_NAME* name{X509_NAME_new()};

  X509NameBuilder() {}

public:
  static auto init() -> X509NameBuilder {
    return X509NameBuilder();
  }

  auto add_entry(NameEntry entry, string_view &&value) -> X509NameBuilder {
    auto field = X509NameEntry::from(entry).to_string().data();
    if (X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, reinterpret_cast<const uint8_t*>(value.data()), -1, -1, 0) != 1) {
      auto err = std::format("Failed to add entry [{}] to X509_NAME", field);
      throw runtime_error(err);
    }
    return std::forward<X509NameBuilder>(*this);
  }

  auto build() -> X509Name {
    return X509Name::own(name);
  }
};

}  // namespace openssl::x509
