#pragma once

// Records the agents exchange through the shared-memory state store.
//
//   routeguard-ingest  --(rg.routes)-->  routeguard-validator  --(rg.verdicts)-->  routeguard-alert
//
// Slot i of rg.verdicts always holds the verdict for slot i of rg.routes, so
// the validator needs no key lookup. Records are trivially copyable and are
// copied byte for byte into and out of the store.

#include <cstdint>
#include <type_traits>

#include "routeguard/aspa.hpp"
#include "routeguard/prefix.hpp"
#include "routeguard/rpki.hpp"

namespace rg::pipeline {

inline constexpr const char* kRoutesTable = "rg.routes";
inline constexpr const char* kVerdictsTable = "rg.verdicts";
inline constexpr std::size_t kMaxPathLen = 48;

// One (peer, prefix) route as last announced.
struct RouteRecord {
  Prefix prefix;
  std::uint32_t peer_asn = 0;
  std::uint32_t origin = 0;  // 0 = unknown (AS_SET origin or empty path)
  std::uint32_t path_len = 0;
  std::uint32_t path[kMaxPathLen] = {};
  std::uint64_t ingest_ns = 0;  // CLOCK_MONOTONIC when ingest wrote the record
  std::int64_t bgp_time = 0;    // timestamp from the BGP feed
  std::uint8_t origin_is_set = 0;
  std::uint8_t path_truncated = 0;
};

struct VerdictRecord {
  Prefix prefix;
  std::uint32_t peer_asn = 0;
  std::uint32_t origin = 0;
  RovState rov = RovState::NotFound;
  AspaState aspa = AspaState::Unknown;
  std::uint64_t ingest_ns = 0;
  std::uint64_t validated_ns = 0;
};

static_assert(std::is_trivially_copyable_v<RouteRecord>);
static_assert(std::is_trivially_copyable_v<VerdictRecord>);

}  // namespace rg::pipeline
