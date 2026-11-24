#include "routeguard/aspa.hpp"
#include "test_framework.hpp"

RG_TEST(aspa_hop_check) {
  rg::AspaTable t;
  t.add(64500, {3356, 174, 3356});
  RG_CHECK(t.check_hop(64500, 3356) == rg::HopCheck::ProviderPlus);
  RG_CHECK(t.check_hop(64500, 64666) == rg::HopCheck::NotProviderPlus);
  RG_CHECK(t.check_hop(64501, 3356) == rg::HopCheck::NoAttestation);
}

// TODO(stage 4): once verify_upstream/verify_downstream exist, add the test
// vectors from the ASPA verification draft here (valid path, route leak,
// unknown because of missing attestations, prepending).
