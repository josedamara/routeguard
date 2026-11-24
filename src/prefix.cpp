#include "routeguard/prefix.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <bit>
#include <string>

#include "text_util.hpp"

namespace rg {

std::optional<Prefix> Prefix::parse(std::string_view text) {
  text = detail::trim(text);
  const auto slash = text.find('/');
  if (slash == std::string_view::npos) return std::nullopt;

  const auto len = detail::parse_int<int>(text.substr(slash + 1));
  if (!len) return std::nullopt;

  Prefix p;
  const std::string addr(text.substr(0, slash));  // inet_pton needs a C string
  const bool v6 = addr.find(':') != std::string::npos;
  p.family_ = v6 ? Family::V6 : Family::V4;
  if (inet_pton(v6 ? AF_INET6 : AF_INET, addr.c_str(), p.bytes_.data()) != 1) return std::nullopt;

  if (*len < 0 || *len > p.max_length()) return std::nullopt;
  p.length_ = static_cast<std::uint8_t>(*len);

  // Canonical form only: every bit after the prefix length must be zero.
  for (int i = p.length_; i < p.max_length(); ++i) {
    if (p.bit(i)) return std::nullopt;
  }
  return p;
}

std::optional<Prefix> Prefix::from_bytes(Family family, const std::uint8_t* bytes, std::size_t n_bytes,
                                         int length) {
  Prefix p;
  p.family_ = family;
  if (length < 0 || length > p.max_length()) return std::nullopt;
  const auto needed = static_cast<std::size_t>((length + 7) / 8);
  if (n_bytes < needed) return std::nullopt;
  std::copy(bytes, bytes + needed, p.bytes_.begin());
  p.length_ = static_cast<std::uint8_t>(length);
  p.clear_host_bits();
  return p;
}

void Prefix::clear_host_bits() noexcept {
  const int full = length_ / 8;
  const int rem = length_ % 8;
  int first_zero = full;
  if (rem != 0) {
    bytes_[static_cast<std::size_t>(full)] &= static_cast<std::uint8_t>(0xFFU << (8 - rem));
    first_zero = full + 1;
  }
  std::fill(bytes_.begin() + first_zero, bytes_.end(), std::uint8_t{0});
}

int Prefix::common_length(const Prefix& a, const Prefix& b, int limit) noexcept {
  for (int i = 0; i * 8 < limit; ++i) {
    const auto x = static_cast<std::uint8_t>(a.bytes_[static_cast<std::size_t>(i)] ^
                                             b.bytes_[static_cast<std::size_t>(i)]);
    if (x != 0) return std::min(limit, i * 8 + std::countl_zero(x));
  }
  return limit;
}

Prefix Prefix::truncated(int len) const noexcept {
  Prefix p = *this;
  p.length_ = static_cast<std::uint8_t>(len);
  p.clear_host_bits();
  return p;
}

std::size_t Prefix::hash() const noexcept {
  // FNV-1a over the significant bytes, the length and the family.
  std::uint64_t h = 1469598103934665603ULL;
  auto mix = [&h](std::uint8_t byte) {
    h ^= byte;
    h *= 1099511628211ULL;
  };
  const int n = (length_ + 7) / 8;
  for (int i = 0; i < n; ++i) mix(bytes_[static_cast<std::size_t>(i)]);
  mix(length_);
  mix(static_cast<std::uint8_t>(family_));
  return static_cast<std::size_t>(h);
}

bool Prefix::covers(const Prefix& other) const noexcept {
  if (family_ != other.family_ || length_ > other.length_) return false;
  const auto full_bytes = static_cast<std::ptrdiff_t>(length_ / 8);
  if (!std::equal(bytes_.begin(), bytes_.begin() + full_bytes, other.bytes_.begin())) return false;
  const int rem = length_ % 8;
  if (rem == 0) return true;
  const auto mask = static_cast<std::uint8_t>(0xFFU << (8 - rem));
  const auto i = static_cast<std::size_t>(full_bytes);
  return (bytes_[i] & mask) == (other.bytes_[i] & mask);
}

std::string Prefix::to_string() const {
  char buf[INET6_ADDRSTRLEN] = {};
  inet_ntop(family_ == Family::V6 ? AF_INET6 : AF_INET, bytes_.data(), buf, sizeof buf);
  return std::string(buf) + '/' + std::to_string(length_);
}

}  // namespace rg
