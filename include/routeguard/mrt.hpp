#pragma once

// Streaming decoder for MRT (RFC 6396) BGP4MP archives, the binary format
// RIPE RIS and RouteViews publish raw BGP UPDATE messages in. Each UPDATE is
// expanded into one BgpUpdate per announced or withdrawn prefix.
//
// Supported: BGP4MP and BGP4MP_ET, subtypes MESSAGE / MESSAGE_AS4 and their
// _LOCAL variants; IPv4 NLRI plus MP_REACH / MP_UNREACH (RFC 4760) for IPv6;
// AS_PATH with 2- or 4-byte ASNs and AS4_PATH merging (RFC 6793).
// Skipped (counted, not errors): state changes, non-UPDATE messages,
// ADD-PATH subtypes, non-unicast SAFIs, TABLE_DUMP_V2 RIB snapshots.

#include <cstdint>
#include <istream>
#include <span>
#include <vector>

#include "routeguard/bgp_update.hpp"

namespace rg {

struct MrtStats {
  std::uint64_t records = 0;    // MRT records read
  std::uint64_t updates = 0;    // BGP UPDATE messages decoded
  std::uint64_t prefixes = 0;   // BgpUpdate entries produced
  std::uint64_t skipped = 0;    // records we deliberately ignore
  std::uint64_t malformed = 0;  // records that failed bounds/format checks
  std::uint64_t bytes = 0;      // input bytes consumed
};

enum class MrtResult : std::uint8_t { Decoded, Skipped, Malformed };

// Decodes one MRT record (header fields already split out). Appends any
// per-prefix updates to `out`. Never reads outside `body`.
MrtResult decode_mrt_record(std::uint32_t timestamp, std::uint16_t type, std::uint16_t subtype,
                            std::span<const std::uint8_t> body, std::vector<BgpUpdate>& out);

// Decodes a buffer of concatenated MRT records; stops at the first truncated
// record. Returns the number of bytes consumed. Used by the fuzzer.
std::size_t decode_mrt_buffer(std::span<const std::uint8_t> data, std::vector<BgpUpdate>& out,
                              MrtStats* stats = nullptr);

class MrtReader {
 public:
  explicit MrtReader(std::istream& in) : in_(in) {}

  // Reads the next record and appends its updates to `out` (possibly none).
  // Returns false at end of input or on a truncated record.
  bool next(std::vector<BgpUpdate>& out);

  const MrtStats& stats() const noexcept { return stats_; }

 private:
  std::istream& in_;
  std::vector<std::uint8_t> body_;
  MrtStats stats_;
};

}  // namespace rg
