#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace rg {

enum class Family : std::uint8_t { V4, V6 };

// An IPv4 or IPv6 prefix such as "192.0.2.0/24" or "2001:db8::/32".
//
// Addresses are stored in network byte order in a fixed 16-byte array, so the
// type is trivially copyable and needs no heap allocation. Prefixes are kept
// canonical: parse() rejects inputs with host bits set (e.g. "10.0.0.1/8").
class Prefix {
 public:
  static constexpr int kMaxBytes = 16;

  Prefix() = default;

  // Returns nullopt for malformed input, out-of-range lengths or host bits set.
  static std::optional<Prefix> parse(std::string_view text);

  // Builds a prefix from raw network-order bytes, e.g. a BGP NLRI. Needs at
  // least ceil(length / 8) bytes. Host bits are cleared rather than rejected.
  static std::optional<Prefix> from_bytes(Family family, const std::uint8_t* bytes, std::size_t n_bytes,
                                          int length);

  // Number of leading bits a and b share, capped at `limit`. Ignores family.
  static int common_length(const Prefix& a, const Prefix& b, int limit) noexcept;

  // This prefix shortened to `len` bits (len <= length()).
  Prefix truncated(int len) const noexcept;

  std::size_t hash() const noexcept;

  Family family() const noexcept { return family_; }
  int length() const noexcept { return length_; }
  int max_length() const noexcept { return family_ == Family::V4 ? 32 : 128; }

  // Bit i of the address, counting from the most significant bit (i = 0).
  bool bit(int i) const noexcept {
    return ((bytes_[static_cast<std::size_t>(i / 8)] >> (7 - i % 8)) & 1U) != 0;
  }

  // True if this prefix is equal to or less specific than `other` and
  // `other` falls inside it. Different families never cover each other.
  bool covers(const Prefix& other) const noexcept;

  std::string to_string() const;

  friend bool operator==(const Prefix&, const Prefix&) = default;

 private:
  void clear_host_bits() noexcept;

  std::array<std::uint8_t, kMaxBytes> bytes_{};
  std::uint8_t length_ = 0;
  Family family_ = Family::V4;
};

struct PrefixHash {
  std::size_t operator()(const Prefix& p) const noexcept { return p.hash(); }
};

}  // namespace rg
