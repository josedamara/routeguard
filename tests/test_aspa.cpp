#include <sstream>
#include <vector>

#include "routeguard/aspa.hpp"
#include "test_framework.hpp"

using rg::AspaState;
using Path = std::vector<std::uint32_t>;  // received order: neighbour first, origin last

// AS numbers used below:
//   1 origin, 2 = provider of 1, 3 = provider of 2 (a "tier 1"),
//   4 and 5 = other tier 1s that peer laterally, 6 = the receiving side.
//   100 = some unrelated provider that tier 1s list, so their ASPA exists
//   but does not include the ASes they merely peer with.

RG_TEST(aspa_hop_check) {
  rg::AspaTable t;
  t.add(64500, {3356, 174, 3356});
  RG_CHECK(t.check_hop(64500, 3356) == rg::HopCheck::ProviderPlus);
  RG_CHECK(t.check_hop(64500, 64666) == rg::HopCheck::NotProviderPlus);
  RG_CHECK(t.check_hop(64501, 3356) == rg::HopCheck::NoAttestation);
}

RG_TEST(aspa_upstream) {
  rg::AspaTable t;
  t.add(1, {2});
  t.add(2, {3});
  RG_CHECK(t.verify_upstream(Path{3, 2, 1}) == AspaState::Valid);
  RG_CHECK(t.verify_upstream(Path{3, 3, 3, 2, 2, 1}) == AspaState::Valid);  // prepends collapse
  RG_CHECK(t.verify_upstream(Path{1}) == AspaState::Valid);
  RG_CHECK(t.verify_upstream(Path{}) == AspaState::Invalid);
  RG_CHECK(t.verify_upstream(Path{9, 3, 2, 1}) == AspaState::Unknown);  // 3 has no ASPA

  // Customer 10 leaks a route it learned from its provider 11.
  t.add(1, {11});
  t.add(10, {11});
  t.add(11, {200});
  RG_CHECK(t.verify_upstream(Path{10, 11, 1}) == AspaState::Invalid);
}

RG_TEST(aspa_downstream_valley_free_paths) {
  rg::AspaTable t;
  t.add(1, {2});
  t.add(2, {3});
  t.add(3, {100});
  t.add(4, {100});
  t.add(6, {3});
  // Up 1->2->3, then down 3->6.
  RG_CHECK(t.verify_downstream(Path{6, 3, 2, 1}) == AspaState::Valid);

  // Up to 3, one lateral peering 3--4 at the top, down 4->6: still valid.
  t.add(6, {4});
  RG_CHECK(t.verify_downstream(Path{6, 4, 3, 2, 1}) == AspaState::Valid);
  RG_CHECK(t.verify_downstream(Path{2, 1}) == AspaState::Valid);  // N <= 2
}

RG_TEST(aspa_downstream_detects_route_leak) {
  rg::AspaTable t;
  t.add(1, {2});
  t.add(2, {3});
  t.add(3, {100});
  t.add(4, {100});
  t.add(5, {100});
  t.add(6, {5});
  // 3--4 and 4--5 are both lateral peerings: a valley. 4 leaked it.
  RG_CHECK(t.verify_downstream(Path{6, 5, 4, 3, 2, 1}) == AspaState::Invalid);
}

RG_TEST(aspa_downstream_unknown_without_attestations) {
  rg::AspaTable t;
  t.add(1, {2});  // only the origin publishes an ASPA
  RG_CHECK(t.verify_downstream(Path{6, 3, 2, 1}) == AspaState::Unknown);
}

RG_TEST(aspa_as_set_is_invalid) {
  rg::AspaTable t;
  t.add(1, {2});
  RG_CHECK(t.verify(Path{2, 1}, rg::AspaDirection::Downstream, true) == AspaState::Invalid);
  RG_CHECK(t.verify(Path{2, 1}, rg::AspaDirection::Downstream, false) == AspaState::Valid);
}

RG_TEST(aspa_loads_csv) {
  std::istringstream csv(
      "Customer ASN,Providers\n"
      "AS43,AS293\n"
      "AS64500,AS3356 AS174\n"
      "AS64501,\n"  // AS0-style: no providers at all
      "ASx,AS1\n"
      "AS64502,AS1 nope\n");
  rg::AspaTable t;
  const auto stats = rg::load_aspa_csv(csv, t);
  RG_CHECK(stats.loaded == 3);
  RG_CHECK(stats.skipped == 2);
  RG_CHECK(t.check_hop(64500, 174) == rg::HopCheck::ProviderPlus);
  RG_CHECK(t.check_hop(64501, 174) == rg::HopCheck::NotProviderPlus);
}
