#pragma once

// Small internal string helpers. Not part of the public API.

#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>
#include <vector>

namespace rg::detail {

inline std::string_view trim(std::string_view s) noexcept {
  constexpr std::string_view kSpace = " \t\r\n";
  const auto first = s.find_first_not_of(kSpace);
  if (first == std::string_view::npos) return {};
  const auto last = s.find_last_not_of(kSpace);
  return s.substr(first, last - first + 1);
}

// Splits on `delim`, keeping empty fields ("a||b" -> {"a", "", "b"}).
inline std::vector<std::string_view> split(std::string_view s, char delim) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  while (true) {
    const auto pos = s.find(delim, start);
    if (pos == std::string_view::npos) {
      out.push_back(s.substr(start));
      return out;
    }
    out.push_back(s.substr(start, pos - start));
    start = pos + 1;
  }
}

template <typename T>
std::optional<T> parse_int(std::string_view s) noexcept {
  if (s.empty()) return std::nullopt;
  T value{};
  const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
  if (ec != std::errc{} || ptr != s.data() + s.size()) return std::nullopt;
  return value;
}

// Accepts "13335", "AS13335" and "as13335".
inline std::optional<std::uint32_t> parse_asn(std::string_view s) noexcept {
  if (s.size() >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's')) s.remove_prefix(2);
  return parse_int<std::uint32_t>(s);
}

}  // namespace rg::detail
