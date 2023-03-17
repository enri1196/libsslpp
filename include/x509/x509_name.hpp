#pragma once

#include <openssl/x509.h>

#include "bio.hpp"
#include "internal/ssl_interface.hpp"

namespace openssl {

class X509NameBuilder;

class X509Name {
private:
  using SSLPtr = std::shared_ptr<X509_NAME>;
  SSLPtr m_ssl_type;

  X509Name() : m_ssl_type(X509_NAME_new(), X509_NAME_free) {}

public:
  X509Name(const X509Name &) = default;
  X509Name(X509Name &&) noexcept = default;
  auto operator=(const X509Name &) -> X509Name & = default;
  auto operator=(X509Name &&) noexcept -> X509Name & = default;
  explicit X509Name(X509_NAME *ptr,
                    std::function<void(X509_NAME *)> free_fn = X509_NAME_free)
      : m_ssl_type(ptr, free_fn) {}
  ~X509Name() = default;

  auto as_ptr() const noexcept -> X509_NAME * { return m_ssl_type.get(); }

  template <class Builder = X509NameBuilder>
    requires std::is_same_v<Builder, X509NameBuilder>
  static auto init() -> Builder {
    return Builder();
  }

  auto to_string() -> Expected<std::string_view> {
    auto bio = SSLBio::init();
    X509_NAME_print_ex(bio.as_ptr(), this->as_ptr(), 0, XN_FLAG_RFC2253);
    return bio.get_mem_ptr();
  }
};

class X509NameEntry {
public:
  enum class entries {
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

private:
  entries m_ent;

public:
  X509NameEntry() = delete;
  explicit X509NameEntry(entries ent) : m_ent(ent) {}

  auto to_string() const -> std::string_view {
    switch (m_ent) {
    case entries::C:
      return "C";
    case entries::CN:
      return "CN";
    case entries::DC:
      return "DC";
    case entries::Email:
      return "Email";
    case entries::GivenName:
      return "GivenName";
    case entries::L:
      return "L";
    case entries::O:
      return "O";
    case entries::OU:
      return "OU";
    case entries::SN:
      return "SN";
    case entries::ST:
      return "ST";
    case entries::Surname:
      return "Surname";
    case entries::UID:
      return "UID";
    }
  }
};

class X509NameBuilder {
private:
  X509_NAME* name{X509_NAME_new()};

  friend X509Name;

  X509NameBuilder() = default;

public:
  X509NameBuilder(const X509NameBuilder &) = delete;
  X509NameBuilder(X509NameBuilder &&) noexcept = default;
  auto operator=(const X509NameBuilder &) -> X509NameBuilder & = delete;
  auto operator=(X509NameBuilder &&) noexcept -> X509NameBuilder & = default;

  auto add_entry(const X509NameEntry&& entry, const std::string_view&& value) -> X509NameBuilder {
    auto field = entry.to_string().data();
    X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, reinterpret_cast<const std::uint8_t*>(value.data()), -1, -1, 0);
    return std::forward<X509NameBuilder>(*this);
  }

  auto build() -> X509Name {
    return X509Name(name);
  }
};

} // namespace openssl
