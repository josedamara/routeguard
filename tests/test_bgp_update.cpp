#include <vector>

#include "routeguard/bgp_update.hpp"
#include "test_framework.hpp"

RG_TEST(bgpdump_announce) {
  const auto u = rg::parse_bgpdump_line(
      "BGP4MP|1763337600|A|192.0.2.254|64510|1.1.1.0/24|64510 3356 13335|IGP|192.0.2.254|0|0||NAG||");
  RG_CHECK(u.has_value());
  RG_CHECK(u->kind == rg::UpdateKind::Announce);
  RG_CHECK(u->timestamp == 1763337600);
  RG_CHECK(u->peer_ip == "192.0.2.254");
  RG_CHECK(u->peer_asn == 64510);
  RG_CHECK(u->prefix.to_string() == "1.1.1.0/24");
  RG_CHECK((u->as_path == std::vector<std::uint32_t>{64510, 3356, 13335}));
  RG_CHECK(u->origin_asn() == 13335U);
}

RG_TEST(bgpdump_withdraw_and_table_dump) {
  const auto w = rg::parse_bgpdump_line("BGP4MP|1763337600|W|192.0.2.254|64510|1.1.1.0/24");
  RG_CHECK(w.has_value());
  RG_CHECK(w->kind == rg::UpdateKind::Withdraw);
  RG_CHECK(!w->origin_asn().has_value());

  const auto b = rg::parse_bgpdump_line("TABLE_DUMP2|1763337600|B|192.0.2.254|64510|2001:db8::/32|64510 64502|IGP");
  RG_CHECK(b.has_value());
  RG_CHECK(b->origin_asn() == 64502U);
}

RG_TEST(bgpdump_as_set_origin) {
  const auto u = rg::parse_bgpdump_line("BGP4MP|1|A|192.0.2.254|64510|2001:db8::/32|64510 64502 {64520,64521}|IGP");
  RG_CHECK(u.has_value());
  RG_CHECK(u->origin_is_set);
  RG_CHECK(!u->origin_asn().has_value());
}

RG_TEST(bgpdump_rejects_garbage) {
  RG_CHECK(!rg::parse_bgpdump_line("").has_value());
  RG_CHECK(!rg::parse_bgpdump_line("BGP4MP|1|STATE|192.0.2.254|64510|1|2").has_value());
  RG_CHECK(!rg::parse_bgpdump_line("BGP4MP|x|A|192.0.2.254|64510|1.1.1.0/24|1 2").has_value());
  RG_CHECK(!rg::parse_bgpdump_line("BGP4MP|1|A|192.0.2.254|64510|1.1.1.0/24").has_value());  // no path
  RG_CHECK(!rg::parse_bgpdump_line("BGP4MP|1|A|192.0.2.254|64510|1.1.1.0/24|1 abc").has_value());
}
