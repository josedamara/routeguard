#include "routeguard/aspa.hpp"

#include <algorithm>
#include <string>

#include "text_util.hpp"

namespace rg {

std::string_view to_string(AspaState s) noexcept {
  switch (s) {
    case AspaState::Valid: return "VALID";
    case AspaState::Invalid: return "INVALID";
    case AspaState::Unknown: return "UNKNOWN";
  }
  return "?";
}

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

namespace {

// Removes AS prepending (consecutive duplicates) and reverses the path so
// that index 0 is the origin, matching the draft's AS(1) .. AS(N) numbering
// with AS(i) == path[i - 1].
std::vector<std::uint32_t> origin_first(std::span<const std::uint32_t> as_path) {
  std::vector<std::uint32_t> out;
  out.reserve(as_path.size());
  for (auto it = as_path.rbegin(); it != as_path.rend(); ++it) {
    if (out.empty() || out.back() != *it) out.push_back(*it);
  }
  return out;
}

}  // namespace

// Upstream: every hop from the origin must go customer -> provider.
//   any hop "Not Provider+"   -> Invalid
//   any hop "No Attestation"  -> Unknown
//   otherwise                 -> Valid
AspaState AspaTable::verify_upstream(std::span<const std::uint32_t> as_path) const {
  const auto p = origin_first(as_path);
  const std::size_t n = p.size();
  if (n == 0) return AspaState::Invalid;
  if (n == 1) return AspaState::Valid;
  bool unknown = false;
  for (std::size_t i = 0; i + 1 < n; ++i) {
    const auto hop = check_hop(p[i], p[i + 1]);
    if (hop == HopCheck::NotProviderPlus) return AspaState::Invalid;
    if (hop == HopCheck::NoAttestation) unknown = true;
  }
  return unknown ? AspaState::Unknown : AspaState::Valid;
}

// Downstream: the path may climb from the origin (up-ramp), cross at most one
// lateral peering at the top, and descend to us (down-ramp). With N ASes:
//   u_max = length of the longest possible up-ramp (stops at the first hop
//           that is provably not customer->provider), v_max likewise for the
//           down-ramp seen from our end. If u_max + v_max < N the ramps
//           cannot meet: Invalid.
//   u_min / v_min are the ramps provable from attestations alone. If they
//           cannot meet: Unknown. Otherwise Valid.
AspaState AspaTable::verify_downstream(std::span<const std::uint32_t> as_path) const {
  const auto p = origin_first(as_path);
  const std::size_t n = p.size();
  if (n == 0) return AspaState::Invalid;
  if (n <= 2) return AspaState::Valid;

  // Draft indices are 1-based: AS(i) == p[i - 1].
  auto up = [&](std::size_t i) { return check_hop(p[i - 1], p[i]); };        // hop(AS(i), AS(i+1))
  auto down = [&](std::size_t i) { return check_hop(p[i - 1], p[i - 2]); };  // hop(AS(i), AS(i-1))

  std::size_t u_max = n, u_min = n;
  for (std::size_t u = 1; u < n; ++u) {
    const auto hop = up(u);
    if (u_min == n && hop != HopCheck::ProviderPlus) u_min = u;
    if (hop == HopCheck::NotProviderPlus) {
      u_max = u;
      break;
    }
  }
  std::size_t v_max = n, v_min = n;
  for (std::size_t v = n; v >= 2; --v) {
    const auto hop = down(v);
    if (v_min == n && hop != HopCheck::ProviderPlus) v_min = n - v + 1;
    if (hop == HopCheck::NotProviderPlus) {
      v_max = n - v + 1;
      break;
    }
  }
  if (u_max + v_max < n) return AspaState::Invalid;
  if (u_min + v_min < n) return AspaState::Unknown;
  return AspaState::Valid;
}

AspaState AspaTable::verify(std::span<const std::uint32_t> as_path, AspaDirection direction,
                            bool has_as_set) const {
  if (has_as_set) return AspaState::Invalid;
  return direction == AspaDirection::Upstream ? verify_upstream(as_path) : verify_downstream(as_path);
}

CsvLoadStats load_aspa_csv(std::istream& in, AspaTable& table) {
  CsvLoadStats stats;
  std::string raw;
  while (std::getline(in, raw)) {
    const auto line = detail::trim(raw);
    if (line.empty() || line.front() == '#') continue;
    const auto fields = detail::split(line, ',');
    const auto customer = detail::parse_asn(detail::trim(fields[0]));
    if (!customer || fields.size() < 2) {
      if (!detail::trim(fields[0]).starts_with("Customer")) ++stats.skipped;
      continue;
    }
    std::vector<std::uint32_t> providers;
    bool ok = true;
    for (const auto token : detail::split(detail::trim(fields[1]), ' ')) {
      if (token.empty()) continue;
      const auto asn = detail::parse_asn(token);
      if (!asn) {
        ok = false;
        break;
      }
      providers.push_back(*asn);
    }
    if (!ok) {
      ++stats.skipped;
      continue;
    }
    table.add(*customer, std::move(providers));
    ++stats.loaded;
  }
  return stats;
}

}  // namespace rg
