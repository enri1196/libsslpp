///
// expected - An implementation of std::expected with extensions
// Written in 2017 by Sy Brand (tartanllama@gmail.com, @TartanLlama)
//
// Documentation available at http://tl.tartanllama.xyz/
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to the
// public domain worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software. If not, see
// <http://creativecommons.org/publicdomain/zero/1.0/>.
///
#pragma once

#include <exception>
#include <functional>
#include <type_traits>
#include <utility>

namespace tl {
template <class T, class E> class expected;

class monostate {};

struct in_place_t {
  explicit in_place_t() = default;
};
static constexpr in_place_t in_place{};

template <class E> class unexpected {
public:
  static_assert(!std::is_same<E, void>::value, "E must not be void");

  unexpected() = delete;
  constexpr explicit unexpected(const E &e) : m_val(e) {}

  constexpr explicit unexpected(E &&e) : m_val(std::move(e)) {}

  template <class... Args, typename std::enable_if<std::is_constructible<
                               E, Args &&...>::value>::type * = nullptr>
  constexpr explicit unexpected(Args &&...args)
      : m_val(std::forward<Args>(args)...) {}
  template <
      class U, class... Args,
      typename std::enable_if<std::is_constructible<
          E, std::initializer_list<U> &, Args &&...>::value>::type * = nullptr>
  constexpr explicit unexpected(std::initializer_list<U> l, Args &&...args)
      : m_val(l, std::forward<Args>(args)...) {}

  constexpr const E &value() const & { return m_val; }
  constexpr E &value() & { return m_val; }
  constexpr E &&value() && { return std::move(m_val); }
  constexpr const E &&value() const && { return std::move(m_val); }

private:
  E m_val;
};

template <class E> unexpected(E) -> unexpected<E>;

template <class E>
constexpr bool operator==(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() == rhs.value();
}
template <class E>
constexpr bool operator!=(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() != rhs.value();
}
template <class E>
constexpr bool operator<(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() < rhs.value();
}
template <class E>
constexpr bool operator<=(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() <= rhs.value();
}
template <class E>
constexpr bool operator>(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() > rhs.value();
}
template <class E>
constexpr bool operator>=(const unexpected<E> &lhs, const unexpected<E> &rhs) {
  return lhs.value() >= rhs.value();
}

template <class E>
unexpected<typename std::decay<E>::type> make_unexpected(E &&e) {
  return unexpected<typename std::decay<E>::type>(std::forward<E>(e));
}

struct unexpect_t {
  unexpect_t() = default;
};
static constexpr unexpect_t unexpect{};

namespace detail {
template <typename E> [[noreturn]] constexpr void throw_exception([[maybe_unused]]E &&e) {

  __builtin_unreachable();
}

template <class T> using remove_const_t = typename std::remove_const<T>::type;
template <class T>
using remove_reference_t = typename std::remove_reference<T>::type;
template <class T> using decay_t = typename std::decay<T>::type;
template <bool E, class T = void>
using enable_if_t = typename std::enable_if<E, T>::type;
template <bool B, class T, class F>
using conditional_t = typename std::conditional<B, T, F>::type;

template <class...> struct conjunction : std::true_type {};
template <class B> struct conjunction<B> : B {};
template <class B, class... Bs>
struct conjunction<B, Bs...>
    : std::conditional<bool(B::value), conjunction<Bs...>, B>::type {};
# 269 "expected.hpp"
template <typename Fn, typename... Args,

          typename = enable_if_t<std::is_member_pointer<decay_t<Fn>>::value>,
          int = 0>
constexpr auto invoke(Fn &&f, Args &&...args) noexcept(
    noexcept(std::mem_fn(f)(std::forward<Args>(args)...)))
    -> decltype(std::mem_fn(f)(std::forward<Args>(args)...)) {
  return std::mem_fn(f)(std::forward<Args>(args)...);
}

template <typename Fn, typename... Args,
          typename = enable_if_t<!std::is_member_pointer<decay_t<Fn>>::value>>
constexpr auto invoke(Fn &&f, Args &&...args) noexcept(
    noexcept(std::forward<Fn>(f)(std::forward<Args>(args)...)))
    -> decltype(std::forward<Fn>(f)(std::forward<Args>(args)...)) {
  return std::forward<Fn>(f)(std::forward<Args>(args)...);
}

template <class F, class, class... Us> struct invoke_result_impl;

template <class F, class... Us>
struct invoke_result_impl<
    F,
    decltype(detail::invoke(std::declval<F>(), std::declval<Us>()...), void()),
    Us...> {
  using type =
      decltype(detail::invoke(std::declval<F>(), std::declval<Us>()...));
};

template <class F, class... Us>
using invoke_result = invoke_result_impl<F, void, Us...>;

template <class F, class... Us>
using invoke_result_t = typename invoke_result<F, Us...>::type;
# 315 "expected.hpp"
namespace swap_adl_tests {

struct tag {};

template <class T> tag swap(T &, T &);
template <class T, std::size_t N> tag swap(T (&a)[N], T (&b)[N]);

template <class, class> std::false_type can_swap(...) noexcept(false);
template <class T, class U,
          class = decltype(swap(std::declval<T &>(), std::declval<U &>()))>
std::true_type can_swap(int) noexcept(noexcept(swap(std::declval<T &>(),
                                                    std::declval<U &>())));

template <class, class> std::false_type uses_std(...);
template <class T, class U>
std::is_same<decltype(swap(std::declval<T &>(), std::declval<U &>())), tag>
uses_std(int);

template <class T>
struct is_std_swap_noexcept
    : std::integral_constant<bool,
                             std::is_nothrow_move_constructible<T>::value &&
                                 std::is_nothrow_move_assignable<T>::value> {};

template <class T, std::size_t N>
struct is_std_swap_noexcept<T[N]> : is_std_swap_noexcept<T> {};

template <class T, class U>
struct is_adl_swap_noexcept
    : std::integral_constant<bool, noexcept(can_swap<T, U>(0))> {};
} // namespace swap_adl_tests

template <class T, class U = T>
struct is_swappable
    : std::integral_constant<
          bool,
          decltype(detail::swap_adl_tests::can_swap<T, U>(0))::value &&
              (!decltype(detail::swap_adl_tests::uses_std<T, U>(0))::value ||
               (std::is_move_assignable<T>::value &&
                std::is_move_constructible<T>::value))> {};

template <class T, std::size_t N>
struct is_swappable<T[N], T[N]>
    : std::integral_constant<
          bool,
          decltype(detail::swap_adl_tests::can_swap<T[N], T[N]>(0))::value &&
              (!decltype(detail::swap_adl_tests::uses_std<T[N], T[N]>(
                   0))::value ||
               is_swappable<T, T>::value)> {};

template <class T, class U = T>
struct is_nothrow_swappable
    : std::integral_constant<
          bool,
          is_swappable<T, U>::value &&
              ((decltype(detail::swap_adl_tests::uses_std<T, U>(0))::value &&
                detail::swap_adl_tests::is_std_swap_noexcept<T>::value) ||
               (!decltype(detail::swap_adl_tests::uses_std<T, U>(0))::value &&
                detail::swap_adl_tests::is_adl_swap_noexcept<T, U>::value))> {};

template <class T> struct is_expected_impl : std::false_type {};
template <class T, class E>
struct is_expected_impl<expected<T, E>> : std::true_type {};
template <class T> using is_expected = is_expected_impl<decay_t<T>>;

template <class T, class E, class U>
using expected_enable_forward_value = detail::enable_if_t<
    std::is_constructible<T, U &&>::value &&
    !std::is_same<detail::decay_t<U>, in_place_t>::value &&
    !std::is_same<expected<T, E>, detail::decay_t<U>>::value &&
    !std::is_same<unexpected<E>, detail::decay_t<U>>::value>;

template <class T, class E, class U, class G, class UR, class GR>
using expected_enable_from_other = detail::enable_if_t<
    std::is_constructible<T, UR>::value &&
    std::is_constructible<E, GR>::value &&
    !std::is_constructible<T, expected<U, G> &>::value &&
    !std::is_constructible<T, expected<U, G> &&>::value &&
    !std::is_constructible<T, const expected<U, G> &>::value &&
    !std::is_constructible<T, const expected<U, G> &&>::value &&
    !std::is_convertible<expected<U, G> &, T>::value &&
    !std::is_convertible<expected<U, G> &&, T>::value &&
    !std::is_convertible<const expected<U, G> &, T>::value &&
    !std::is_convertible<const expected<U, G> &&, T>::value>;

template <class T, class U>
using is_void_or = conditional_t<std::is_void<T>::value, std::true_type, U>;

template <class T>
using is_copy_constructible_or_void =
    is_void_or<T, std::is_copy_constructible<T>>;

template <class T>
using is_move_constructible_or_void =
    is_void_or<T, std::is_move_constructible<T>>;

template <class T>
using is_copy_assignable_or_void = is_void_or<T, std::is_copy_assignable<T>>;

template <class T>
using is_move_assignable_or_void = is_void_or<T, std::is_move_assignable<T>>;

} // namespace detail

namespace detail {
struct no_init_t {};
static constexpr no_init_t no_init{};

template <class T, class E, bool = std::is_trivially_destructible<T>::value,
          bool = std::is_trivially_destructible<E>::value>
struct expected_storage_base {
  constexpr expected_storage_base() : m_val(T{}), m_has_val(true) {}
  constexpr expected_storage_base(no_init_t) : m_no_init(), m_has_val(false) {}

  template <class... Args,
            detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * =
                nullptr>
  constexpr expected_storage_base(in_place_t, Args &&...args)
      : m_val(std::forward<Args>(args)...), m_has_val(true) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, std::initializer_list<U> il,
                                  Args &&...args)
      : m_val(il, std::forward<Args>(args)...), m_has_val(true) {}
  template <class... Args,
            detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * =
                nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t,
                                           std::initializer_list<U> il,
                                           Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() {
    if (m_has_val) {
      m_val.~T();
    } else {
      m_unexpect.~unexpected<E>();
    }
  }
  union {
    T m_val;
    unexpected<E> m_unexpect;
    char m_no_init;
  };
  bool m_has_val;
};

template <class T, class E> struct expected_storage_base<T, E, true, true> {
  constexpr expected_storage_base() : m_val(T{}), m_has_val(true) {}
  constexpr expected_storage_base(no_init_t) : m_no_init(), m_has_val(false) {}

  template <class... Args,
            detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * =
                nullptr>
  constexpr expected_storage_base(in_place_t, Args &&...args)
      : m_val(std::forward<Args>(args)...), m_has_val(true) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, std::initializer_list<U> il,
                                  Args &&...args)
      : m_val(il, std::forward<Args>(args)...), m_has_val(true) {}
  template <class... Args,
            detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * =
                nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t,
                                           std::initializer_list<U> il,
                                           Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() = default;
  union {
    T m_val;
    unexpected<E> m_unexpect;
    char m_no_init;
  };
  bool m_has_val;
};

template <class T, class E> struct expected_storage_base<T, E, true, false> {
  constexpr expected_storage_base() : m_val(T{}), m_has_val(true) {}
  constexpr expected_storage_base(no_init_t) : m_no_init(), m_has_val(false) {}

  template <class... Args,
            detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * =
                nullptr>
  constexpr expected_storage_base(in_place_t, Args &&...args)
      : m_val(std::forward<Args>(args)...), m_has_val(true) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, std::initializer_list<U> il,
                                  Args &&...args)
      : m_val(il, std::forward<Args>(args)...), m_has_val(true) {}
  template <class... Args,
            detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * =
                nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t,
                                           std::initializer_list<U> il,
                                           Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() {
    if (!m_has_val) {
      m_unexpect.~unexpected<E>();
    }
  }

  union {
    T m_val;
    unexpected<E> m_unexpect;
    char m_no_init;
  };
  bool m_has_val;
};

template <class T, class E> struct expected_storage_base<T, E, false, true> {
  constexpr expected_storage_base() : m_val(T{}), m_has_val(true) {}
  constexpr expected_storage_base(no_init_t) : m_no_init(), m_has_val(false) {}

  template <class... Args,
            detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * =
                nullptr>
  constexpr expected_storage_base(in_place_t, Args &&...args)
      : m_val(std::forward<Args>(args)...), m_has_val(true) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected_storage_base(in_place_t, std::initializer_list<U> il,
                                  Args &&...args)
      : m_val(il, std::forward<Args>(args)...), m_has_val(true) {}
  template <class... Args,
            detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * =
                nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t,
                                           std::initializer_list<U> il,
                                           Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() {
    if (m_has_val) {
      m_val.~T();
    }
  }
  union {
    T m_val;
    unexpected<E> m_unexpect;
    char m_no_init;
  };
  bool m_has_val;
};

template <class E> struct expected_storage_base<void, E, false, true> {

  expected_storage_base() : m_has_val(true) {}

  constexpr expected_storage_base(no_init_t) : m_val(), m_has_val(false) {}

  constexpr expected_storage_base(in_place_t) : m_has_val(true) {}

  template <class... Args,
            detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * =
                nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t,
                                           std::initializer_list<U> il,
                                           Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() = default;
  struct dummy {};
  union {
    unexpected<E> m_unexpect;
    dummy m_val;
  };
  bool m_has_val;
};

template <class E> struct expected_storage_base<void, E, false, false> {
  constexpr expected_storage_base() : m_dummy(), m_has_val(true) {}
  constexpr expected_storage_base(no_init_t) : m_dummy(), m_has_val(false) {}

  constexpr expected_storage_base(in_place_t) : m_dummy(), m_has_val(true) {}

  template <class... Args,
            detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * =
                nullptr>
  constexpr explicit expected_storage_base(unexpect_t, Args &&...args)
      : m_unexpect(std::forward<Args>(args)...), m_has_val(false) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected_storage_base(unexpect_t,
                                           std::initializer_list<U> il,
                                           Args &&...args)
      : m_unexpect(il, std::forward<Args>(args)...), m_has_val(false) {}

  ~expected_storage_base() {
    if (!m_has_val) {
      m_unexpect.~unexpected<E>();
    }
  }

  union {
    unexpected<E> m_unexpect;
    char m_dummy;
  };
  bool m_has_val;
};

template <class T, class E>
struct expected_operations_base : expected_storage_base<T, E> {
  using expected_storage_base<T, E>::expected_storage_base;

  template <class... Args> void construct(Args &&...args) noexcept {
    new (std::addressof(this->m_val)) T(std::forward<Args>(args)...);
    this->m_has_val = true;
  }

  template <class Rhs> void construct_with(Rhs &&rhs) noexcept {
    new (std::addressof(this->m_val)) T(std::forward<Rhs>(rhs).get());
    this->m_has_val = true;
  }

  template <class... Args> void construct_error(Args &&...args) noexcept {
    new (std::addressof(this->m_unexpect))
        unexpected<E>(std::forward<Args>(args)...);
    this->m_has_val = false;
  }
# 808 "expected.hpp"
  void assign(const expected_operations_base &rhs) noexcept {
    if (!this->m_has_val && rhs.m_has_val) {
      geterr().~unexpected<E>();
      construct(rhs.get());
    } else {
      assign_common(rhs);
    }
  }

  void assign(expected_operations_base &&rhs) noexcept {
    if (!this->m_has_val && rhs.m_has_val) {
      geterr().~unexpected<E>();
      construct(std::move(rhs).get());
    } else {
      assign_common(rhs);
    }
  }

  template <class Rhs> void assign_common(Rhs &&rhs) {
    if (this->m_has_val) {
      if (rhs.m_has_val) {
        get() = std::forward<Rhs>(rhs).get();
      } else {
        destroy_val();
        construct_error(std::forward<Rhs>(rhs).geterr());
      }
    } else {
      if (!rhs.m_has_val) {
        geterr() = std::forward<Rhs>(rhs).geterr();
      }
    }
  }

  bool has_value() const { return this->m_has_val; }

  constexpr T &get() & { return this->m_val; }
  constexpr const T &get() const & { return this->m_val; }
  constexpr T &&get() && { return std::move(this->m_val); }

  constexpr const T &&get() const && { return std::move(this->m_val); }

  constexpr unexpected<E> &geterr() & { return this->m_unexpect; }
  constexpr const unexpected<E> &geterr() const & { return this->m_unexpect; }
  constexpr unexpected<E> &&geterr() && { return std::move(this->m_unexpect); }

  constexpr const unexpected<E> &&geterr() const && {
    return std::move(this->m_unexpect);
  }

  constexpr void destroy_val() { get().~T(); }
};

template <class E>
struct expected_operations_base<void, E> : expected_storage_base<void, E> {
  using expected_storage_base<void, E>::expected_storage_base;

  template <class... Args> void construct() noexcept { this->m_has_val = true; }

  template <class Rhs> void construct_with(Rhs &&) noexcept {
    this->m_has_val = true;
  }

  template <class... Args> void construct_error(Args &&...args) noexcept {
    new (std::addressof(this->m_unexpect))
        unexpected<E>(std::forward<Args>(args)...);
    this->m_has_val = false;
  }

  template <class Rhs> void assign(Rhs &&rhs) noexcept {
    if (!this->m_has_val) {
      if (rhs.m_has_val) {
        geterr().~unexpected<E>();
        construct();
      } else {
        geterr() = std::forward<Rhs>(rhs).geterr();
      }
    } else {
      if (!rhs.m_has_val) {
        construct_error(std::forward<Rhs>(rhs).geterr());
      }
    }
  }

  bool has_value() const { return this->m_has_val; }

  constexpr unexpected<E> &geterr() & { return this->m_unexpect; }
  constexpr const unexpected<E> &geterr() const & { return this->m_unexpect; }
  constexpr unexpected<E> &&geterr() && { return std::move(this->m_unexpect); }

  constexpr const unexpected<E> &&geterr() const && {
    return std::move(this->m_unexpect);
  }

  constexpr void destroy_val() {}
};

template <class T, class E,
          bool = is_void_or<T, std::is_trivially_copy_constructible<T>>::value
              &&std::is_trivially_copy_constructible<E>::value>
struct expected_copy_base : expected_operations_base<T, E> {
  using expected_operations_base<T, E>::expected_operations_base;
};

template <class T, class E>
struct expected_copy_base<T, E, false> : expected_operations_base<T, E> {
  using expected_operations_base<T, E>::expected_operations_base;

  expected_copy_base() = default;
  expected_copy_base(const expected_copy_base &rhs)
      : expected_operations_base<T, E>(no_init) {
    if (rhs.has_value()) {
      this->construct_with(rhs);
    } else {
      this->construct_error(rhs.geterr());
    }
  }

  expected_copy_base(expected_copy_base &&rhs) = default;
  expected_copy_base &operator=(const expected_copy_base &rhs) = default;
  expected_copy_base &operator=(expected_copy_base &&rhs) = default;
};

template <class T, class E,
          bool = is_void_or<T, std::is_trivially_move_constructible<T>>::value
              &&std::is_trivially_move_constructible<E>::value>
struct expected_move_base : expected_copy_base<T, E> {
  using expected_copy_base<T, E>::expected_copy_base;
};

template <class T, class E>
struct expected_move_base<T, E, false> : expected_copy_base<T, E> {
  using expected_copy_base<T, E>::expected_copy_base;

  expected_move_base() = default;
  expected_move_base(const expected_move_base &rhs) = default;

  expected_move_base(expected_move_base &&rhs) noexcept(
      std::is_nothrow_move_constructible<T>::value)
      : expected_copy_base<T, E>(no_init) {
    if (rhs.has_value()) {
      this->construct_with(std::move(rhs));
    } else {
      this->construct_error(std::move(rhs.geterr()));
    }
  }
  expected_move_base &operator=(const expected_move_base &rhs) = default;
  expected_move_base &operator=(expected_move_base &&rhs) = default;
};

template <
    class T, class E,
    bool = is_void_or<T, conjunction<std::is_trivially_copy_assignable<T>,
                                     std::is_trivially_copy_constructible<T>,
                                     std::is_trivially_destructible<T>>>::value
        &&std::is_trivially_copy_assignable<E>::value
            &&std::is_trivially_copy_constructible<E>::value
                &&std::is_trivially_destructible<E>::value>
struct expected_copy_assign_base : expected_move_base<T, E> {
  using expected_move_base<T, E>::expected_move_base;
};

template <class T, class E>
struct expected_copy_assign_base<T, E, false> : expected_move_base<T, E> {
  using expected_move_base<T, E>::expected_move_base;

  expected_copy_assign_base() = default;
  expected_copy_assign_base(const expected_copy_assign_base &rhs) = default;

  expected_copy_assign_base(expected_copy_assign_base &&rhs) = default;
  expected_copy_assign_base &operator=(const expected_copy_assign_base &rhs) {
    this->assign(rhs);
    return *this;
  }
  expected_copy_assign_base &
  operator=(expected_copy_assign_base &&rhs) = default;
};

template <class T, class E,
          bool =
              is_void_or<T, conjunction<std::is_trivially_destructible<T>,
                                        std::is_trivially_move_constructible<T>,
                                        std::is_trivially_move_assignable<T>>>::
                  value &&std::is_trivially_destructible<E>::value
                      &&std::is_trivially_move_constructible<E>::value
                          &&std::is_trivially_move_assignable<E>::value>
struct expected_move_assign_base : expected_copy_assign_base<T, E> {
  using expected_copy_assign_base<T, E>::expected_copy_assign_base;
};

template <class T, class E>
struct expected_move_assign_base<T, E, false>
    : expected_copy_assign_base<T, E> {
  using expected_copy_assign_base<T, E>::expected_copy_assign_base;

  expected_move_assign_base() = default;
  expected_move_assign_base(const expected_move_assign_base &rhs) = default;

  expected_move_assign_base(expected_move_assign_base &&rhs) = default;

  expected_move_assign_base &
  operator=(const expected_move_assign_base &rhs) = default;

  expected_move_assign_base &
  operator=(expected_move_assign_base &&rhs) noexcept(
      std::is_nothrow_move_constructible<T>::value
          &&std::is_nothrow_move_assignable<T>::value) {
    this->assign(std::move(rhs));
    return *this;
  }
};

template <class T, class E,
          bool EnableCopy = (is_copy_constructible_or_void<T>::value &&
                             std::is_copy_constructible<E>::value),
          bool EnableMove = (is_move_constructible_or_void<T>::value &&
                             std::is_move_constructible<E>::value)>
struct expected_delete_ctor_base {
  expected_delete_ctor_base() = default;
  expected_delete_ctor_base(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base(expected_delete_ctor_base &&) noexcept = default;
  expected_delete_ctor_base &
  operator=(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base &
  operator=(expected_delete_ctor_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_ctor_base<T, E, true, false> {
  expected_delete_ctor_base() = default;
  expected_delete_ctor_base(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base(expected_delete_ctor_base &&) noexcept = delete;
  expected_delete_ctor_base &
  operator=(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base &
  operator=(expected_delete_ctor_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_ctor_base<T, E, false, true> {
  expected_delete_ctor_base() = default;
  expected_delete_ctor_base(const expected_delete_ctor_base &) = delete;
  expected_delete_ctor_base(expected_delete_ctor_base &&) noexcept = default;
  expected_delete_ctor_base &
  operator=(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base &
  operator=(expected_delete_ctor_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_ctor_base<T, E, false, false> {
  expected_delete_ctor_base() = default;
  expected_delete_ctor_base(const expected_delete_ctor_base &) = delete;
  expected_delete_ctor_base(expected_delete_ctor_base &&) noexcept = delete;
  expected_delete_ctor_base &
  operator=(const expected_delete_ctor_base &) = default;
  expected_delete_ctor_base &
  operator=(expected_delete_ctor_base &&) noexcept = default;
};

template <class T, class E,
          bool EnableCopy = (is_copy_constructible_or_void<T>::value &&
                             std::is_copy_constructible<E>::value &&
                             is_copy_assignable_or_void<T>::value &&
                             std::is_copy_assignable<E>::value),
          bool EnableMove = (is_move_constructible_or_void<T>::value &&
                             std::is_move_constructible<E>::value &&
                             is_move_assignable_or_void<T>::value &&
                             std::is_move_assignable<E>::value)>
struct expected_delete_assign_base {
  expected_delete_assign_base() = default;
  expected_delete_assign_base(const expected_delete_assign_base &) = default;
  expected_delete_assign_base(expected_delete_assign_base &&) noexcept =
      default;
  expected_delete_assign_base &
  operator=(const expected_delete_assign_base &) = default;
  expected_delete_assign_base &
  operator=(expected_delete_assign_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_assign_base<T, E, true, false> {
  expected_delete_assign_base() = default;
  expected_delete_assign_base(const expected_delete_assign_base &) = default;
  expected_delete_assign_base(expected_delete_assign_base &&) noexcept =
      default;
  expected_delete_assign_base &
  operator=(const expected_delete_assign_base &) = default;
  expected_delete_assign_base &
  operator=(expected_delete_assign_base &&) noexcept = delete;
};

template <class T, class E>
struct expected_delete_assign_base<T, E, false, true> {
  expected_delete_assign_base() = default;
  expected_delete_assign_base(const expected_delete_assign_base &) = default;
  expected_delete_assign_base(expected_delete_assign_base &&) noexcept =
      default;
  expected_delete_assign_base &
  operator=(const expected_delete_assign_base &) = delete;
  expected_delete_assign_base &
  operator=(expected_delete_assign_base &&) noexcept = default;
};

template <class T, class E>
struct expected_delete_assign_base<T, E, false, false> {
  expected_delete_assign_base() = default;
  expected_delete_assign_base(const expected_delete_assign_base &) = default;
  expected_delete_assign_base(expected_delete_assign_base &&) noexcept =
      default;
  expected_delete_assign_base &
  operator=(const expected_delete_assign_base &) = delete;
  expected_delete_assign_base &
  operator=(expected_delete_assign_base &&) noexcept = delete;
};

struct default_constructor_tag {
  explicit constexpr default_constructor_tag() = default;
};

template <class T, class E,
          bool Enable =
              std::is_default_constructible<T>::value || std::is_void<T>::value>
struct expected_default_ctor_base {
  constexpr expected_default_ctor_base() noexcept = default;
  constexpr expected_default_ctor_base(
      expected_default_ctor_base const &) noexcept = default;
  constexpr expected_default_ctor_base(expected_default_ctor_base &&) noexcept =
      default;
  expected_default_ctor_base &
  operator=(expected_default_ctor_base const &) noexcept = default;
  expected_default_ctor_base &
  operator=(expected_default_ctor_base &&) noexcept = default;

  constexpr explicit expected_default_ctor_base(default_constructor_tag) {}
};

template <class T, class E> struct expected_default_ctor_base<T, E, false> {
  constexpr expected_default_ctor_base() noexcept = delete;
  constexpr expected_default_ctor_base(
      expected_default_ctor_base const &) noexcept = default;
  constexpr expected_default_ctor_base(expected_default_ctor_base &&) noexcept =
      default;
  expected_default_ctor_base &
  operator=(expected_default_ctor_base const &) noexcept = default;
  expected_default_ctor_base &
  operator=(expected_default_ctor_base &&) noexcept = default;

  constexpr explicit expected_default_ctor_base(default_constructor_tag) {}
};
} // namespace detail

template <class E> class bad_expected_access : public std::exception {
public:
  explicit bad_expected_access(E e) : m_val(std::move(e)) {}

  virtual const char *what() const noexcept override {
    return "Bad expected access";
  }

  const E &error() const & { return m_val; }
  E &error() & { return m_val; }
  const E &&error() const && { return std::move(m_val); }
  E &&error() && { return std::move(m_val); }

private:
  E m_val;
};
template <class T, class E>
class expected : private detail::expected_move_assign_base<T, E>,
                 private detail::expected_delete_ctor_base<T, E>,
                 private detail::expected_delete_assign_base<T, E>,
                 private detail::expected_default_ctor_base<T, E> {
  static_assert(!std::is_reference<T>::value, "T must not be a reference");
  static_assert(!std::is_same<T, std::remove_cv<in_place_t>::type>::value,
                "T must not be in_place_t");
  static_assert(!std::is_same<T, std::remove_cv<unexpect_t>::type>::value,
                "T must not be unexpect_t");
  static_assert(
      !std::is_same<T, typename std::remove_cv<unexpected<E>>::type>::value,
      "T must not be unexpected<E>");
  static_assert(!std::is_reference<E>::value, "E must not be a reference");

  T *valptr() { return std::addressof(this->m_val); }
  const T *valptr() const { return std::addressof(this->m_val); }
  unexpected<E> *errptr() { return std::addressof(this->m_unexpect); }
  const unexpected<E> *errptr() const {
    return std::addressof(this->m_unexpect);
  }

  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr U &val() {
    return this->m_val;
  }
  constexpr unexpected<E> &err() { return this->m_unexpect; }

  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr const U &val() const {
    return this->m_val;
  }
  constexpr const unexpected<E> &err() const { return this->m_unexpect; }

  using impl_base = detail::expected_move_assign_base<T, E>;
  using ctor_base = detail::expected_default_ctor_base<T, E>;

public:
  typedef T value_type;
  typedef E error_type;
  typedef unexpected<E> unexpected_type;

  template <class F> constexpr auto and_then(F &&f) & {
    return and_then_impl(*this, std::forward<F>(f));
  }
  template <class F> constexpr auto and_then(F &&f) && {
    return and_then_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F> constexpr auto and_then(F &&f) const & {
    return and_then_impl(*this, std::forward<F>(f));
  }

  template <class F> constexpr auto and_then(F &&f) const && {
    return and_then_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F> constexpr auto map(F &&f) & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F> constexpr auto map(F &&f) && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F> constexpr auto map(F &&f) const & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F> constexpr auto map(F &&f) const && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F> constexpr auto transform(F &&f) & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F> constexpr auto transform(F &&f) && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F> constexpr auto transform(F &&f) const & {
    return expected_map_impl(*this, std::forward<F>(f));
  }
  template <class F> constexpr auto transform(F &&f) const && {
    return expected_map_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F> constexpr auto map_error(F &&f) & {
    return map_error_impl(*this, std::forward<F>(f));
  }
  template <class F> constexpr auto map_error(F &&f) && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F> constexpr auto map_error(F &&f) const & {
    return map_error_impl(*this, std::forward<F>(f));
  }
  template <class F> constexpr auto map_error(F &&f) const && {
    return map_error_impl(std::move(*this), std::forward<F>(f));
  }
  template <class F> expected constexpr or_else(F &&f) & {
    return or_else_impl(*this, std::forward<F>(f));
  }

  template <class F> expected constexpr or_else(F &&f) && {
    return or_else_impl(std::move(*this), std::forward<F>(f));
  }

  template <class F> expected constexpr or_else(F &&f) const & {
    return or_else_impl(*this, std::forward<F>(f));
  }

  template <class F> expected constexpr or_else(F &&f) const && {
    return or_else_impl(std::move(*this), std::forward<F>(f));
  }

  constexpr expected() = default;
  constexpr expected(const expected &rhs) = default;
  constexpr expected(expected &&rhs) = default;
  expected &operator=(const expected &rhs) = default;
  expected &operator=(expected &&rhs) = default;

  template <class... Args,
            detail::enable_if_t<std::is_constructible<T, Args &&...>::value> * =
                nullptr>
  constexpr expected(in_place_t, Args &&...args)
      : impl_base(in_place, std::forward<Args>(args)...),
        ctor_base(detail::default_constructor_tag{}) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr expected(in_place_t, std::initializer_list<U> il, Args &&...args)
      : impl_base(in_place, il, std::forward<Args>(args)...),
        ctor_base(detail::default_constructor_tag{}) {}

  template <class G = E,
            detail::enable_if_t<std::is_constructible<E, const G &>::value> * =
                nullptr,
            detail::enable_if_t<!std::is_convertible<const G &, E>::value> * =
                nullptr>
  explicit constexpr expected(const unexpected<G> &e)
      : impl_base(unexpect, e.value()),
        ctor_base(detail::default_constructor_tag{}) {}

  template <
      class G = E,
      detail::enable_if_t<std::is_constructible<E, const G &>::value> * =
          nullptr,
      detail::enable_if_t<std::is_convertible<const G &, E>::value> * = nullptr>
  constexpr expected(unexpected<G> const &e)
      : impl_base(unexpect, e.value()),
        ctor_base(detail::default_constructor_tag{}) {}

  template <
      class G = E,
      detail::enable_if_t<std::is_constructible<E, G &&>::value> * = nullptr,
      detail::enable_if_t<!std::is_convertible<G &&, E>::value> * = nullptr>
  explicit constexpr expected(unexpected<G> &&e) noexcept(
      std::is_nothrow_constructible<E, G &&>::value)
      : impl_base(unexpect, std::move(e.value())),
        ctor_base(detail::default_constructor_tag{}) {}

  template <
      class G = E,
      detail::enable_if_t<std::is_constructible<E, G &&>::value> * = nullptr,
      detail::enable_if_t<std::is_convertible<G &&, E>::value> * = nullptr>
  constexpr expected(unexpected<G> &&e) noexcept(
      std::is_nothrow_constructible<E, G &&>::value)
      : impl_base(unexpect, std::move(e.value())),
        ctor_base(detail::default_constructor_tag{}) {}

  template <class... Args,
            detail::enable_if_t<std::is_constructible<E, Args &&...>::value> * =
                nullptr>
  constexpr explicit expected(unexpect_t, Args &&...args)
      : impl_base(unexpect, std::forward<Args>(args)...),
        ctor_base(detail::default_constructor_tag{}) {}

  template <class U, class... Args,
            detail::enable_if_t<std::is_constructible<
                E, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  constexpr explicit expected(unexpect_t, std::initializer_list<U> il,
                              Args &&...args)
      : impl_base(unexpect, il, std::forward<Args>(args)...),
        ctor_base(detail::default_constructor_tag{}) {}

  template <class U, class G,
            detail::enable_if_t<!(std::is_convertible<U const &, T>::value &&
                                  std::is_convertible<G const &, E>::value)> * =
                nullptr,
            detail::expected_enable_from_other<T, E, U, G, const U &, const G &>
                * = nullptr>
  explicit constexpr expected(const expected<U, G> &rhs)
      : ctor_base(detail::default_constructor_tag{}) {
    if (rhs.has_value()) {
      this->construct(*rhs);
    } else {
      this->construct_error(rhs.error());
    }
  }

  template <class U, class G,
            detail::enable_if_t<(std::is_convertible<U const &, T>::value &&
                                 std::is_convertible<G const &, E>::value)> * =
                nullptr,
            detail::expected_enable_from_other<T, E, U, G, const U &, const G &>
                * = nullptr>
  constexpr expected(const expected<U, G> &rhs)
      : ctor_base(detail::default_constructor_tag{}) {
    if (rhs.has_value()) {
      this->construct(*rhs);
    } else {
      this->construct_error(rhs.error());
    }
  }

  template <
      class U, class G,
      detail::enable_if_t<!(std::is_convertible<U &&, T>::value &&
                            std::is_convertible<G &&, E>::value)> * = nullptr,
      detail::expected_enable_from_other<T, E, U, G, U &&, G &&> * = nullptr>
  explicit constexpr expected(expected<U, G> &&rhs)
      : ctor_base(detail::default_constructor_tag{}) {
    if (rhs.has_value()) {
      this->construct(std::move(*rhs));
    } else {
      this->construct_error(std::move(rhs.error()));
    }
  }

  template <
      class U, class G,
      detail::enable_if_t<(std::is_convertible<U &&, T>::value &&
                           std::is_convertible<G &&, E>::value)> * = nullptr,
      detail::expected_enable_from_other<T, E, U, G, U &&, G &&> * = nullptr>
  constexpr expected(expected<U, G> &&rhs)
      : ctor_base(detail::default_constructor_tag{}) {
    if (rhs.has_value()) {
      this->construct(std::move(*rhs));
    } else {
      this->construct_error(std::move(rhs.error()));
    }
  }

  template <
      class U = T,
      detail::enable_if_t<!std::is_convertible<U &&, T>::value> * = nullptr,
      detail::expected_enable_forward_value<T, E, U> * = nullptr>
  explicit constexpr expected(U &&v) : expected(in_place, std::forward<U>(v)) {}

  template <
      class U = T,
      detail::enable_if_t<std::is_convertible<U &&, T>::value> * = nullptr,
      detail::expected_enable_forward_value<T, E, U> * = nullptr>
  constexpr expected(U &&v) : expected(in_place, std::forward<U>(v)) {}

  template <
      class U = T, class G = T,
      detail::enable_if_t<std::is_nothrow_constructible<T, U &&>::value> * =
          nullptr,
      detail::enable_if_t<!std::is_void<G>::value> * = nullptr,
      detail::enable_if_t<
          (!std::is_same<expected<T, E>, detail::decay_t<U>>::value &&
           !detail::conjunction<std::is_scalar<T>,
                                std::is_same<T, detail::decay_t<U>>>::value &&
           std::is_constructible<T, U>::value &&
           std::is_assignable<G &, U>::value &&
           std::is_nothrow_move_constructible<E>::value)> * = nullptr>
  expected &operator=(U &&v) {
    if (has_value()) {
      val() = std::forward<U>(v);
    } else {
      err().~unexpected<E>();
      ::new (valptr()) T(std::forward<U>(v));
      this->m_has_val = true;
    }

    return *this;
  }

  template <
      class U = T, class G = T,
      detail::enable_if_t<!std::is_nothrow_constructible<T, U &&>::value> * =
          nullptr,
      detail::enable_if_t<!std::is_void<U>::value> * = nullptr,
      detail::enable_if_t<
          (!std::is_same<expected<T, E>, detail::decay_t<U>>::value &&
           !detail::conjunction<std::is_scalar<T>,
                                std::is_same<T, detail::decay_t<U>>>::value &&
           std::is_constructible<T, U>::value &&
           std::is_assignable<G &, U>::value &&
           std::is_nothrow_move_constructible<E>::value)> * = nullptr>
  expected &operator=(U &&v) {
    if (has_value()) {
      val() = std::forward<U>(v);
    } else {
      auto tmp = std::move(err());
      err().~unexpected<E>();
# 1668 "expected.hpp"
      ::new (valptr()) T(std::forward<U>(v));
      this->m_has_val = true;
    }

    return *this;
  }

  template <class G = E,
            detail::enable_if_t<std::is_nothrow_copy_constructible<G>::value &&
                                std::is_assignable<G &, G>::value> * = nullptr>
  expected &operator=(const unexpected<G> &rhs) {
    if (!has_value()) {
      err() = rhs;
    } else {
      this->destroy_val();
      ::new (errptr()) unexpected<E>(rhs);
      this->m_has_val = false;
    }

    return *this;
  }

  template <class G = E,
            detail::enable_if_t<std::is_nothrow_move_constructible<G>::value &&
                                std::is_move_assignable<G>::value> * = nullptr>
  expected &operator=(unexpected<G> &&rhs) noexcept {
    if (!has_value()) {
      err() = std::move(rhs);
    } else {
      this->destroy_val();
      ::new (errptr()) unexpected<E>(std::move(rhs));
      this->m_has_val = false;
    }

    return *this;
  }

  template <class... Args, detail::enable_if_t<std::is_nothrow_constructible<
                               T, Args &&...>::value> * = nullptr>
  void emplace(Args &&...args) {
    if (has_value()) {
      val().~T();
    } else {
      err().~unexpected<E>();
      this->m_has_val = true;
    }
    ::new (valptr()) T(std::forward<Args>(args)...);
  }

  template <class... Args, detail::enable_if_t<!std::is_nothrow_constructible<
                               T, Args &&...>::value> * = nullptr>
  void emplace(Args &&...args) {
    if (has_value()) {
      val().~T();
      ::new (valptr()) T(std::forward<Args>(args)...);
    } else {
      auto tmp = std::move(err());
      err().~unexpected<E>();
      ::new (valptr()) T(std::forward<Args>(args)...);
      this->m_has_val = true;
    }
  }

  template <class U, class... Args,
            detail::enable_if_t<std::is_nothrow_constructible<
                T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  void emplace(std::initializer_list<U> il, Args &&...args) {
    if (has_value()) {
      T t(il, std::forward<Args>(args)...);
      val() = std::move(t);
    } else {
      err().~unexpected<E>();
      ::new (valptr()) T(il, std::forward<Args>(args)...);
      this->m_has_val = true;
    }
  }

  template <class U, class... Args,
            detail::enable_if_t<!std::is_nothrow_constructible<
                T, std::initializer_list<U> &, Args &&...>::value> * = nullptr>
  void emplace(std::initializer_list<U> il, Args &&...args) {
    if (has_value()) {
      T t(il, std::forward<Args>(args)...);
      val() = std::move(t);
    } else {
      auto tmp = std::move(err());
      err().~unexpected<E>();
      ::new (valptr()) T(il, std::forward<Args>(args)...);
      this->m_has_val = true;
    }
  }

private:
  using t_is_void = std::true_type;
  using t_is_not_void = std::false_type;
  using t_is_nothrow_move_constructible = std::true_type;
  using move_constructing_t_can_throw = std::false_type;
  using e_is_nothrow_move_constructible = std::true_type;
  using move_constructing_e_can_throw = std::false_type;

  void swap_where_both_have_value(expected &, t_is_void) noexcept {}

  void swap_where_both_have_value(expected &rhs, t_is_not_void) {
    using std::swap;
    swap(val(), rhs.val());
  }

  void swap_where_only_one_has_value(expected &rhs, t_is_void) noexcept(
      std::is_nothrow_move_constructible<E>::value) {
    ::new (errptr()) unexpected_type(std::move(rhs.err()));
    rhs.err().~unexpected_type();
    std::swap(this->m_has_val, rhs.m_has_val);
  }

  void swap_where_only_one_has_value(expected &rhs, t_is_not_void) {
    swap_where_only_one_has_value_and_t_is_not_void(
        rhs, typename std::is_nothrow_move_constructible<T>::type{},
        typename std::is_nothrow_move_constructible<E>::type{});
  }

  void swap_where_only_one_has_value_and_t_is_not_void(
      expected &rhs, t_is_nothrow_move_constructible,
      e_is_nothrow_move_constructible) noexcept {
    auto temp = std::move(val());
    val().~T();
    ::new (errptr()) unexpected_type(std::move(rhs.err()));
    rhs.err().~unexpected_type();
    ::new (rhs.valptr()) T(std::move(temp));
    std::swap(this->m_has_val, rhs.m_has_val);
  }

  void swap_where_only_one_has_value_and_t_is_not_void(
      expected &rhs, t_is_nothrow_move_constructible,
      move_constructing_e_can_throw) {
    auto temp = std::move(val());
    val().~T();
    ::new (errptr()) unexpected_type(std::move(rhs.err()));
    rhs.err().~unexpected_type();
    ::new (rhs.valptr()) T(std::move(temp));
    std::swap(this->m_has_val, rhs.m_has_val);
  }

  void swap_where_only_one_has_value_and_t_is_not_void(
      expected &rhs, move_constructing_t_can_throw,
      e_is_nothrow_move_constructible) {
    auto temp = std::move(rhs.err());
    rhs.err().~unexpected_type();
    ::new (rhs.valptr()) T(std::move(val()));
    val().~T();
    ::new (errptr()) unexpected_type(std::move(temp));
    std::swap(this->m_has_val, rhs.m_has_val);
  }

public:
  template <class OT = T, class OE = E>
  detail::enable_if_t<detail::is_swappable<OT>::value &&
                      detail::is_swappable<OE>::value &&
                      (std::is_nothrow_move_constructible<OT>::value ||
                       std::is_nothrow_move_constructible<OE>::value)>
  swap(expected &rhs) noexcept(
      std::is_nothrow_move_constructible<T>::value
          &&detail::is_nothrow_swappable<T>::value
              &&std::is_nothrow_move_constructible<E>::value
                  &&detail::is_nothrow_swappable<E>::value) {
    if (has_value() && rhs.has_value()) {
      swap_where_both_have_value(rhs, typename std::is_void<T>::type{});
    } else if (!has_value() && rhs.has_value()) {
      rhs.swap(*this);
    } else if (has_value()) {
      swap_where_only_one_has_value(rhs, typename std::is_void<T>::type{});
    } else {
      using std::swap;
      swap(err(), rhs.err());
    }
  }

  constexpr const T *operator->() const { return valptr(); }
  constexpr T *operator->() { return valptr(); }

  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr const U &operator*() const & {
    return val();
  }
  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr U &operator*() & {
    return val();
  }
  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr const U &&operator*() const && {
    return std::move(val());
  }
  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr U &&operator*() && {
    return std::move(val());
  }

  constexpr bool has_value() const noexcept { return this->m_has_val; }
  constexpr explicit operator bool() const noexcept { return this->m_has_val; }

  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr const U &value() const & {
    if (!has_value())
      detail::throw_exception(bad_expected_access<E>(err().value()));
    return val();
  }
  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr U &value() & {
    if (!has_value())
      detail::throw_exception(bad_expected_access<E>(err().value()));
    return val();
  }
  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr const U &&value() const && {
    if (!has_value())
      detail::throw_exception(bad_expected_access<E>(std::move(err()).value()));
    return std::move(val());
  }
  template <class U = T,
            detail::enable_if_t<!std::is_void<U>::value> * = nullptr>
  constexpr U &&value() && {
    if (!has_value())
      detail::throw_exception(bad_expected_access<E>(std::move(err()).value()));
    return std::move(val());
  }

  constexpr const E &error() const & { return err().value(); }
  constexpr E &error() & { return err().value(); }
  constexpr const E &&error() const && { return std::move(err().value()); }
  constexpr E &&error() && { return std::move(err().value()); }

  template <class U> constexpr T value_or(U &&v) const & {
    static_assert(std::is_copy_constructible<T>::value &&
                      std::is_convertible<U &&, T>::value,
                  "T must be copy-constructible and convertible to from U&&");
    return bool(*this) ? **this : static_cast<T>(std::forward<U>(v));
  }
  template <class U> constexpr T value_or(U &&v) && {
    static_assert(std::is_move_constructible<T>::value &&
                      std::is_convertible<U &&, T>::value,
                  "T must be move-constructible and convertible to from U&&");
    return bool(*this) ? std::move(**this) : static_cast<T>(std::forward<U>(v));
  }
};

namespace detail {
template <class Exp> using exp_t = typename detail::decay_t<Exp>::value_type;
template <class Exp> using err_t = typename detail::decay_t<Exp>::error_type;
template <class Exp, class Ret> using ret_t = expected<Ret, err_t<Exp>>;

template <class Exp, class F,
          detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(),
                                              *std::declval<Exp>()))>
constexpr auto and_then_impl(Exp &&exp, F &&f) {
  static_assert(detail::is_expected<Ret>::value, "F must return an expected");

  return exp.has_value()
             ? detail::invoke(std::forward<F>(f), *std::forward<Exp>(exp))
             : Ret(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F,
          detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>()))>
constexpr auto and_then_impl(Exp &&exp, F &&f) {
  static_assert(detail::is_expected<Ret>::value, "F must return an expected");

  return exp.has_value() ? detail::invoke(std::forward<F>(f))
                         : Ret(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F,
          detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(),
                                              *std::declval<Exp>())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto expected_map_impl(Exp &&exp, F &&f) {
  using result = ret_t<Exp, detail::decay_t<Ret>>;
  return exp.has_value() ? result(detail::invoke(std::forward<F>(f),
                                                 *std::forward<Exp>(exp)))
                         : result(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F,
          detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(),
                                              *std::declval<Exp>())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto expected_map_impl(Exp &&exp, F &&f) {
  using result = expected<void, err_t<Exp>>;
  if (exp.has_value()) {
    detail::invoke(std::forward<F>(f), *std::forward<Exp>(exp));
    return result();
  }

  return result(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F,
          detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto expected_map_impl(Exp &&exp, F &&f) {
  using result = ret_t<Exp, detail::decay_t<Ret>>;
  return exp.has_value() ? result(detail::invoke(std::forward<F>(f)))
                         : result(unexpect, std::forward<Exp>(exp).error());
}

template <class Exp, class F,
          detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto expected_map_impl(Exp &&exp, F &&f) {
  using result = expected<void, err_t<Exp>>;
  if (exp.has_value()) {
    detail::invoke(std::forward<F>(f));
    return result();
  }

  return result(unexpect, std::forward<Exp>(exp).error());
}
template <class Exp, class F,
          detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(),
                                              std::declval<Exp>().error())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto map_error_impl(Exp &&exp, F &&f) {
  using result = expected<exp_t<Exp>, detail::decay_t<Ret>>;
  return exp.has_value()
             ? result(*std::forward<Exp>(exp))
             : result(unexpect, detail::invoke(std::forward<F>(f),
                                               std::forward<Exp>(exp).error()));
}
template <class Exp, class F,
          detail::enable_if_t<!std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(),
                                              std::declval<Exp>().error())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto map_error_impl(Exp &&exp, F &&f) {
  using result = expected<exp_t<Exp>, monostate>;
  if (exp.has_value()) {
    return result(*std::forward<Exp>(exp));
  }

  detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error());
  return result(unexpect, monostate{});
}
template <class Exp, class F,
          detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(),
                                              std::declval<Exp>().error())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto map_error_impl(Exp &&exp, F &&f) {
  using result = expected<exp_t<Exp>, detail::decay_t<Ret>>;
  return exp.has_value()
             ? result()
             : result(unexpect, detail::invoke(std::forward<F>(f),
                                               std::forward<Exp>(exp).error()));
}
template <class Exp, class F,
          detail::enable_if_t<std::is_void<exp_t<Exp>>::value> * = nullptr,
          class Ret = decltype(detail::invoke(std::declval<F>(),
                                              std::declval<Exp>().error())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
auto map_error_impl(Exp &&exp, F &&f) {
  using result = expected<exp_t<Exp>, monostate>;
  if (exp.has_value()) {
    return result();
  }

  detail::invoke(std::forward<F>(f), std::forward<Exp>(exp).error());
  return result(unexpect, monostate{});
}
template <class Exp, class F,
          class Ret = decltype(detail::invoke(std::declval<F>(),
                                              std::declval<Exp>().error())),
          detail::enable_if_t<!std::is_void<Ret>::value> * = nullptr>
constexpr auto or_else_impl(Exp &&exp, F &&f) {
  static_assert(detail::is_expected<Ret>::value, "F must return an expected");
  return exp.has_value() ? std::forward<Exp>(exp)
                         : detail::invoke(std::forward<F>(f),
                                          std::forward<Exp>(exp).error());
}

template <class Exp, class F,
          class Ret = decltype(detail::invoke(std::declval<F>(),
                                              std::declval<Exp>().error())),
          detail::enable_if_t<std::is_void<Ret>::value> * = nullptr>
detail::decay_t<Exp> or_else_impl(Exp &&exp, F &&f) {
  return exp.has_value() ? std::forward<Exp>(exp)
                         : (detail::invoke(std::forward<F>(f),
                                           std::forward<Exp>(exp).error()),
                            std::forward<Exp>(exp));
}

} // namespace detail

template <class T, class E, class U, class F>
constexpr bool operator==(const expected<T, E> &lhs,
                          const expected<U, F> &rhs) {
  return (lhs.has_value() != rhs.has_value())
             ? false
             : (!lhs.has_value() ? lhs.error() == rhs.error() : *lhs == *rhs);
}
template <class T, class E, class U, class F>
constexpr bool operator!=(const expected<T, E> &lhs,
                          const expected<U, F> &rhs) {
  return (lhs.has_value() != rhs.has_value())
             ? true
             : (!lhs.has_value() ? lhs.error() != rhs.error() : *lhs != *rhs);
}
template <class E, class F>
constexpr bool operator==(const expected<void, E> &lhs,
                          const expected<void, F> &rhs) {
  return (lhs.has_value() != rhs.has_value())
             ? false
             : (!lhs.has_value() ? lhs.error() == rhs.error() : true);
}
template <class E, class F>
constexpr bool operator!=(const expected<void, E> &lhs,
                          const expected<void, F> &rhs) {
  return (lhs.has_value() != rhs.has_value())
             ? true
             : (!lhs.has_value() ? lhs.error() == rhs.error() : false);
}

template <class T, class E, class U>
constexpr bool operator==(const expected<T, E> &x, const U &v) {
  return x.has_value() ? *x == v : false;
}
template <class T, class E, class U>
constexpr bool operator==(const U &v, const expected<T, E> &x) {
  return x.has_value() ? *x == v : false;
}
template <class T, class E, class U>
constexpr bool operator!=(const expected<T, E> &x, const U &v) {
  return x.has_value() ? *x != v : true;
}
template <class T, class E, class U>
constexpr bool operator!=(const U &v, const expected<T, E> &x) {
  return x.has_value() ? *x != v : true;
}

template <class T, class E>
constexpr bool operator==(const expected<T, E> &x, const unexpected<E> &e) {
  return x.has_value() ? false : x.error() == e.value();
}
template <class T, class E>
constexpr bool operator==(const unexpected<E> &e, const expected<T, E> &x) {
  return x.has_value() ? false : x.error() == e.value();
}
template <class T, class E>
constexpr bool operator!=(const expected<T, E> &x, const unexpected<E> &e) {
  return x.has_value() ? true : x.error() != e.value();
}
template <class T, class E>
constexpr bool operator!=(const unexpected<E> &e, const expected<T, E> &x) {
  return x.has_value() ? true : x.error() != e.value();
}

template <class T, class E,
          detail::enable_if_t<(std::is_void<T>::value ||
                               std::is_move_constructible<T>::value) &&
                              detail::is_swappable<T>::value &&
                              std::is_move_constructible<E>::value &&
                              detail::is_swappable<E>::value> * = nullptr>
void swap(expected<T, E> &lhs,
          expected<T, E> &rhs) noexcept(noexcept(lhs.swap(rhs))) {
  lhs.swap(rhs);
}
} // namespace tl
