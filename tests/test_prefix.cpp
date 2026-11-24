#include "routeguard/prefix.hpp"
#include "test_framework.hpp"

using rg::Prefix;

RG_TEST(prefix_parses_ipv4_and_ipv6) {
  const auto v4 = Prefix::parse("192.0.2.0/24");
  RG_CHECK(v4.has_value());
  RG_CHECK(v4->family() == rg::Family::V4);
  RG_CHECK(v4->length() == 24);
  RG_CHECK(v4->to_string() == "192.0.2.0/24");

  const auto v6 = Prefix::parse("2001:db8::/32");
  RG_CHECK(v6.has_value());
  RG_CHECK(v6->family() == rg::Family::V6);
  RG_CHECK(v6->to_string() == "2001:db8::/32");

  RG_CHECK(Prefix::parse("0.0.0.0/0").has_value());
  RG_CHECK(Prefix::parse("::/0").has_value());
}

RG_TEST(prefix_rejects_malformed_input) {
  RG_CHECK(!Prefix::parse("192.0.2.0").has_value());      // no length
  RG_CHECK(!Prefix::parse("192.0.2.0/33").has_value());   // too long
  RG_CHECK(!Prefix::parse("192.0.2.0/-1").has_value());
  RG_CHECK(!Prefix::parse("192.0.2.1/24").has_value());   // host bits set
  RG_CHECK(!Prefix::parse("300.0.0.0/8").has_value());
  RG_CHECK(!Prefix::parse("2001:db8::/129").has_value());
  RG_CHECK(!Prefix::parse("garbage/8").has_value());
}

RG_TEST(prefix_covers) {
  const auto p8 = *Prefix::parse("10.0.0.0/8");
  const auto p16 = *Prefix::parse("10.1.0.0/16");
  const auto p12 = *Prefix::parse("10.16.0.0/12");
  const auto other = *Prefix::parse("11.0.0.0/8");
  RG_CHECK(p8.covers(p16));
  RG_CHECK(p8.covers(p8));
  RG_CHECK(!p16.covers(p8));
  RG_CHECK(!other.covers(p16));
  RG_CHECK(!p12.covers(p16));  // 10.1/16 is outside 10.16/12 (non-byte boundary)
  RG_CHECK(!p8.covers(*Prefix::parse("2001:db8::/32")));
}
