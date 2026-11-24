#include <sstream>

#include "routeguard/rpki.hpp"
#include "test_framework.hpp"

using rg::Prefix;
using rg::RovState;

namespace {
Prefix P(const char* s) { return *Prefix::parse(s); }
}  // namespace

RG_TEST(rov_rfc6811_cases) {
  rg::RoaTable t;
  RG_CHECK(t.add({P("192.0.2.0/24"), 24, 64500}));
  RG_CHECK(t.add({P("198.51.100.0/24"), 26, 64501}));

  RG_CHECK(t.validate(P("192.0.2.0/24"), 64500) == RovState::Valid);
  RG_CHECK(t.validate(P("192.0.2.0/24"), 64666) == RovState::Invalid);    // wrong origin
  RG_CHECK(t.validate(P("192.0.2.0/25"), 64500) == RovState::Invalid);    // longer than maxLength
  RG_CHECK(t.validate(P("198.51.100.64/26"), 64501) == RovState::Valid);  // within maxLength
  RG_CHECK(t.validate(P("192.0.2.0/24"), 0) == RovState::Invalid);        // unknown origin
  RG_CHECK(t.validate(P("203.0.113.0/24"), 64500) == RovState::NotFound);
  RG_CHECK(t.validate(P("192.0.0.0/16"), 64500) == RovState::NotFound);   // ROA is more specific
}

RG_TEST(rov_any_matching_roa_wins) {
  rg::RoaTable t;
  t.add({P("10.0.0.0/8"), 8, 64500});     // covers, does not match (too specific route)
  t.add({P("10.1.0.0/16"), 24, 64501});   // covers and matches
  RG_CHECK(t.validate(P("10.1.2.0/24"), 64501) == RovState::Valid);
  RG_CHECK(t.validate(P("10.1.2.0/24"), 64500) == RovState::Invalid);
}

RG_TEST(rov_as0_never_matches) {
  rg::RoaTable t;
  t.add({P("203.0.113.0/24"), 24, 0});
  RG_CHECK(t.validate(P("203.0.113.0/24"), 64500) == RovState::Invalid);
}

RG_TEST(rov_rejects_bad_max_length) {
  rg::RoaTable t;
  RG_CHECK(!t.add({P("192.0.2.0/24"), 23, 64500}));
  RG_CHECK(!t.add({P("192.0.2.0/24"), 33, 64500}));
  RG_CHECK(t.size() == 0);
}

RG_TEST(rov_loads_csv) {
  std::istringstream csv(
      "ASN,IP Prefix,Max Length,Trust Anchor\n"
      "AS13335,1.1.1.0/24,24,apnic\n"
      "# comment\n"
      "\n"
      "64502,2001:db8::/32,48,example\r\n"
      "ASbad,1.1.1.0/24,24,x\n"
      "AS1,1.1.1.0/24,99,x\n");
  rg::RoaTable t;
  const auto stats = rg::load_roas_csv(csv, t);
  RG_CHECK(stats.loaded == 2);
  RG_CHECK(stats.skipped == 2);
  RG_CHECK(t.validate(P("1.1.1.0/24"), 13335) == RovState::Valid);
  RG_CHECK(t.validate(P("2001:db8:5::/48"), 64502) == RovState::Valid);
}
