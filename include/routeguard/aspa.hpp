#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace rg {

// ASPA (Autonomous System Provider Authorization) lets an AS publish the set
// of ASes that are its upstream providers. Unlike ROV, which only checks the
// origin, ASPA lets a router check the *path*, catching route leaks and
// forged-origin hijacks that RPKI ROV cannot see.
//
// Spec: draft-ietf-sidrops-aspa-verification (read the latest revision).

enum class AspaState : std::uint8_t { Valid, Invalid, Unknown };

// Result of checking a single hop: does `customer` attest `provider`?
enum class HopCheck : std::uint8_t { ProviderPlus, NotProviderPlus, NoAttestation };

class AspaTable {
 public:
  // Records that `customer` lists `providers` as its upstream providers.
  void add(std::uint32_t customer, std::vector<std::uint32_t> providers);

  // The per-hop building block used by the verification algorithm.
  HopCheck check_hop(std::uint32_t customer, std::uint32_t provider) const;

  // TODO(stage 4): implement upstream path verification (route received from
  // a customer or lateral peer). `as_path` is in received order: as_path[0]
  // is the neighbour, as_path.back() is the origin. Collapse prepends first.
  AspaState verify_upstream(std::span<const std::uint32_t> as_path) const;

  // TODO(stage 4): downstream verification (route received from a provider).
  AspaState verify_downstream(std::span<const std::uint32_t> as_path) const;

 private:
  std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> providers_;
};

}  // namespace rg
