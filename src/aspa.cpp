#include "routeguard/aspa.hpp"

#include <algorithm>

namespace rg {

void AspaTable::add(std::uint32_t customer, std::vector<std::uint32_t> providers) {
  std::sort(providers.begin(), providers.end());
  providers.erase(std::unique(providers.begin(), providers.end()), providers.end());
  providers_[customer] = std::move(providers);
}

HopCheck AspaTable::check_hop(std::uint32_t customer, std::uint32_t provider) const {
  const auto it = providers_.find(customer);
  if (it == providers_.end()) return HopCheck::NoAttestation;
  return std::binary_search(it->second.begin(), it->second.end(), provider) ? HopCheck::ProviderPlus
                                                                            : HopCheck::NotProviderPlus;
}

AspaState AspaTable::verify_upstream(std::span<const std::uint32_t> /*as_path*/) const {
  // TODO(stage 4): implement the upstream algorithm from
  // draft-ietf-sidrops-aspa-verification using check_hop().
  return AspaState::Unknown;
}

AspaState AspaTable::verify_downstream(std::span<const std::uint32_t> /*as_path*/) const {
  // TODO(stage 4): implement the downstream algorithm (up-ramp / down-ramp).
  return AspaState::Unknown;
}

}  // namespace rg
