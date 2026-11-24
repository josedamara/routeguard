#pragma once

#include <cstddef>
#include <cstdint>
#include <istream>
#include <string_view>
#include <vector>

#include "routeguard/prefix.hpp"
#include "routeguard/prefix_trie.hpp"

namespace rg {

// Route Origin Validation result, as defined in RFC 6811 section 2.
enum class RovState : std::uint8_t { Valid, Invalid, NotFound };

std::string_view to_string(RovState s) noexcept;

// A validated ROA payload (VRP): "AS `asn` may originate `prefix` and any
// more-specific prefix of it up to /`max_length`".
struct Roa {
  Prefix prefix;
  int max_length = 0;
  std::uint32_t asn = 0;
};

class RoaTable {
 public:
  // Returns false (and stores nothing) if max_length is out of range.
  bool add(const Roa& roa);

  // RFC 6811 origin validation of a route for `route` originated by `origin`.
  // Pass origin = 0 when the origin is unknown (e.g. AS_PATH ends in an
  // AS_SET); such a route can never be Valid.
  RovState validate(const Prefix& route, std::uint32_t origin) const;

  std::size_t size() const noexcept { return count_; }

 private:
  const PrefixTrie<std::vector<Roa>>& trie_for(Family f) const { return f == Family::V4 ? v4_ : v6_; }
  PrefixTrie<std::vector<Roa>>& trie_for(Family f) { return f == Family::V4 ? v4_ : v6_; }

  PrefixTrie<std::vector<Roa>> v4_;
  PrefixTrie<std::vector<Roa>> v6_;
  std::size_t count_ = 0;
};

struct CsvLoadStats {
  std::size_t loaded = 0;
  std::size_t skipped = 0;
};

// Loads VRPs in the CSV format produced by Routinator / rpki-client:
//   ASN,IP Prefix,Max Length[,Trust Anchor...]
//   AS13335,1.1.1.0/24,24,apnic
// A header line, blank lines and lines starting with '#' are ignored.
CsvLoadStats load_roas_csv(std::istream& in, RoaTable& table);

}  // namespace rg
