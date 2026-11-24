#pragma once

#include <cstdint>
#include <istream>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "routeguard/rpki.hpp"  // CsvLoadStats

namespace rg {

// ASPA (Autonomous System Provider Authorization) lets an AS publish the set
// of ASes that are its upstream providers. ROV only checks the origin. ASPA
// lets a router check the *path*, which catches route leaks and
// forged-origin hijacks that ROV cannot see.
//
// Implements the verification procedures of draft-ietf-sidrops-aspa-verification.

enum class AspaState : std::uint8_t { Valid, Invalid, Unknown };

std::string_view to_string(AspaState s) noexcept;

// Result of checking a single hop: does `customer` attest `provider`?
enum class HopCheck : std::uint8_t { ProviderPlus, NotProviderPlus, NoAttestation };

// Which kind of neighbour the route was received from.
enum class AspaDirection : std::uint8_t {
  Upstream,    // from a customer or lateral peer: the path must only go "up"
  Downstream,  // from a provider: one up-ramp, at most one peak, one down-ramp
};

class AspaTable {
 public:
  // Records that `customer` lists `providers` as its upstream providers.
  void add(std::uint32_t customer, std::vector<std::uint32_t> providers);

  HopCheck check_hop(std::uint32_t customer, std::uint32_t provider) const;

  // `as_path` is in received order: as_path[0] is the neighbour and
  // as_path.back() is the origin. Prepends are collapsed internally. Pass
  // has_as_set = true if the AS_PATH contained an AS_SET (always Invalid).
  AspaState verify(std::span<const std::uint32_t> as_path, AspaDirection direction,
                   bool has_as_set = false) const;
  AspaState verify_upstream(std::span<const std::uint32_t> as_path) const;
  AspaState verify_downstream(std::span<const std::uint32_t> as_path) const;

  std::size_t size() const noexcept { return providers_.size(); }

 private:
  std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> providers_;
};

// Loads "Customer ASN,Providers" CSV, providers separated by spaces:
//   AS64500,AS3356 AS174
// as written by scripts/fetch_vrps.py. Header and '#' lines are ignored.
CsvLoadStats load_aspa_csv(std::istream& in, AspaTable& table);

}  // namespace rg
