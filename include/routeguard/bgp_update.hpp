#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "routeguard/prefix.hpp"

namespace rg {

enum class UpdateKind : std::uint8_t { Announce, Withdraw };

struct BgpUpdate {
  std::int64_t timestamp = 0;  // seconds since the Unix epoch
  UpdateKind kind = UpdateKind::Announce;
  std::string peer_ip;
  std::uint32_t peer_asn = 0;
  Prefix prefix;
  std::vector<std::uint32_t> as_path;  // AS_SEQUENCE hops; AS_SET members omitted
  bool origin_is_set = false;          // AS_PATH ended in an AS_SET

  // The originating AS, or nullopt for withdrawals, empty paths and paths
  // that end in an AS_SET (whose origin is ambiguous by definition).
  std::optional<std::uint32_t> origin_asn() const;
};

// Parses one line of `bgpdump -m` output, the usual way to turn RIPE RIS /
// RouteViews MRT archives into text:
//   BGP4MP|1700000000|A|192.0.2.1|64500|1.1.1.0/24|64500 3356 13335|IGP|...
//   BGP4MP|1700000000|W|192.0.2.1|64500|1.1.1.0/24
//   TABLE_DUMP2|1700000000|B|192.0.2.1|64500|1.1.1.0/24|64500 13335|IGP|...
// Returns nullopt for malformed lines and record types we do not handle.
std::optional<BgpUpdate> parse_bgpdump_line(std::string_view line);

}  // namespace rg
