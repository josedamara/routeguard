#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "mrt_builder.hpp"
#include "routeguard/mrt.hpp"
#include "test_framework.hpp"

using namespace rgtest;
using Path = std::vector<std::uint32_t>;

namespace {

std::vector<rg::BgpUpdate> decode(const std::vector<std::uint8_t>& bytes, rg::MrtStats* stats = nullptr) {
  std::vector<rg::BgpUpdate> out;
  rg::decode_mrt_buffer(bytes, out, stats);
  return out;
}

UpdateSpec ipv4_announcement() {
  UpdateSpec s;
  s.attrs = as_path_attr({{2, {64510, 3356, 13335}}});
  auto a = nlri({1, 1, 1, 0}, 24);
  auto b = nlri({1, 0, 0, 0}, 24);
  s.nlri = a;
  s.nlri.insert(s.nlri.end(), b.begin(), b.end());
  return s;
}

}  // namespace

RG_TEST(mrt_ipv4_announcement) {
  rg::MrtStats stats;
  const auto ups = decode(mrt_record(ipv4_announcement()), &stats);
  RG_CHECK(ups.size() == 2);
  RG_CHECK(stats.records == 1 && stats.updates == 1 && stats.prefixes == 2 && stats.malformed == 0);
  RG_CHECK(ups[0].kind == rg::UpdateKind::Announce);
  RG_CHECK(ups[0].prefix.to_string() == "1.1.1.0/24");
  RG_CHECK(ups[1].prefix.to_string() == "1.0.0.0/24");
  RG_CHECK(ups[0].as_path == (Path{64510, 3356, 13335}));
  RG_CHECK(ups[0].origin_asn() == 13335U);
  RG_CHECK(ups[0].peer_asn == 64510 && ups[0].peer_ip == "192.0.2.254");
  RG_CHECK(ups[0].timestamp == 1763337600);
}

RG_TEST(mrt_ipv4_withdrawal_and_odd_lengths) {
  UpdateSpec s;
  s.withdrawn = nlri({10, 0x80, 0, 0}, 9);  // 10.128.0.0/9: non-byte-aligned length
  const auto ups = decode(mrt_record(s));
  RG_CHECK(ups.size() == 1);
  RG_CHECK(ups[0].kind == rg::UpdateKind::Withdraw);
  RG_CHECK(ups[0].prefix.to_string() == "10.128.0.0/9");
}

RG_TEST(mrt_ipv6_mp_reach_and_unreach) {
  UpdateSpec s;
  s.attrs = as_path_attr({{2, {64510, 64502}}});
  auto reach = mp_reach_v6(nlri({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01}, 48));
  auto unreach = mp_unreach_v6(nlri({0x20, 0x01, 0x0d, 0xb8}, 32));
  s.attrs.insert(s.attrs.end(), reach.begin(), reach.end());
  s.attrs.insert(s.attrs.end(), unreach.begin(), unreach.end());
  const auto ups = decode(mrt_record(s));
  RG_CHECK(ups.size() == 2);
  RG_CHECK(ups[0].kind == rg::UpdateKind::Withdraw && ups[0].prefix.to_string() == "2001:db8::/32");
  RG_CHECK(ups[1].kind == rg::UpdateKind::Announce && ups[1].prefix.to_string() == "2001:db8:1::/48");
  RG_CHECK(ups[1].origin_asn() == 64502U);
}

RG_TEST(mrt_as_set_origin) {
  UpdateSpec s;
  s.attrs = as_path_attr({{2, {64510, 64502}}, {1, {64520, 64521}}});
  s.nlri = nlri({192, 0, 2, 0}, 24);
  const auto ups = decode(mrt_record(s));
  RG_CHECK(ups.size() == 1);
  RG_CHECK(ups[0].origin_is_set);
  RG_CHECK(!ups[0].origin_asn().has_value());
}

RG_TEST(mrt_two_byte_session_merges_as4_path) {
  UpdateSpec s;
  s.as4 = false;
  s.peer_as = 64510;
  s.attrs = as_path_attr({{2, {64510, 23456, 23456}}}, 2);   // AS_TRANS placeholders
  auto as4 = as_path_attr({{2, {196608, 400000}}}, 4, 17);  // AS4_PATH
  s.attrs.insert(s.attrs.end(), as4.begin(), as4.end());
  s.nlri = nlri({192, 0, 2, 0}, 24);
  const auto ups = decode(mrt_record(s));
  RG_CHECK(ups.size() == 1);
  RG_CHECK(ups[0].as_path == (Path{64510, 196608, 400000}));
}

RG_TEST(mrt_skips_non_update_records) {
  UpdateSpec keepalive;
  keepalive.bgp_type = 4;
  rg::MrtStats stats;
  RG_CHECK(decode(mrt_record(keepalive), &stats).empty());
  RG_CHECK(stats.skipped == 1 && stats.malformed == 0);

  Bytes state_change;  // BGP4MP_STATE_CHANGE_AS4
  state_change.u32(1).u16(16).u16(5).u32(4).u32(0);
  rg::MrtStats stats2;
  RG_CHECK(decode(state_change.data(), &stats2).empty());
  RG_CHECK(stats2.skipped == 1);
}

RG_TEST(mrt_rejects_malformed_records) {
  UpdateSpec bad_prefix;
  bad_prefix.attrs = as_path_attr({{2, {1}}});
  bad_prefix.nlri = {33, 1, 2, 3, 4, 5};  // /33 IPv4
  rg::MrtStats s1;
  RG_CHECK(decode(mrt_record(bad_prefix), &s1).empty());
  RG_CHECK(s1.malformed == 1);

  UpdateSpec bad_attr;
  bad_attr.attrs = {0x40, 2, 200, 2, 1};  // claims 200 bytes, has 2
  rg::MrtStats s2;
  RG_CHECK(decode(mrt_record(bad_attr), &s2).empty());
  RG_CHECK(s2.malformed == 1);

  auto truncated = mrt_record(ipv4_announcement());
  truncated.resize(truncated.size() - 3);  // record length now exceeds the buffer
  std::vector<rg::BgpUpdate> out;
  RG_CHECK(rg::decode_mrt_buffer(truncated, out) == 0);
}

RG_TEST(mrt_stream_reader) {
  std::string blob;
  for (int i = 0; i < 3; ++i) {
    const auto rec = mrt_record(ipv4_announcement());
    blob.append(rec.begin(), rec.end());
  }
  std::istringstream in(blob);
  rg::MrtReader reader(in);
  std::vector<rg::BgpUpdate> out;
  while (reader.next(out)) {
  }
  RG_CHECK(out.size() == 6);
  RG_CHECK(reader.stats().records == 3 && reader.stats().bytes == blob.size());
}

// Poor man's fuzzing: random byte flips, insertions and truncations of valid
// records. Run under ASan/UBSan this proves the decoder never reads out of
// bounds or hits UB on hostile input. CI also runs a libFuzzer target.
RG_TEST(mrt_survives_random_mutations) {
  std::vector<std::vector<std::uint8_t>> seeds;
  seeds.push_back(mrt_record(ipv4_announcement()));
  {
    UpdateSpec s;
    s.attrs = as_path_attr({{2, {64510, 64502}}, {1, {7, 8}}});
    auto reach = mp_reach_v6(nlri({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01}, 48));
    s.attrs.insert(s.attrs.end(), reach.begin(), reach.end());
    seeds.push_back(mrt_record(s));
  }
  std::mt19937 rng(12345);
  std::size_t produced = 0;
  for (int iter = 0; iter < 50'000; ++iter) {
    auto bytes = seeds[static_cast<std::size_t>(iter) % seeds.size()];
    const int edits = 1 + static_cast<int>(rng() % 4);
    for (int e = 0; e < edits; ++e) {
      const std::size_t pos = rng() % bytes.size();
      switch (rng() % 3) {
        case 0: bytes[pos] = static_cast<std::uint8_t>(rng()); break;
        case 1: bytes.insert(bytes.begin() + static_cast<std::ptrdiff_t>(pos), static_cast<std::uint8_t>(rng())); break;
        case 2: bytes.resize(std::max<std::size_t>(1, pos)); break;
      }
    }
    std::vector<rg::BgpUpdate> out;
    const auto used = rg::decode_mrt_buffer(bytes, out);
    RG_CHECK(used <= bytes.size());
    produced += out.size();
  }
  RG_CHECK(produced > 0);  // some mutations still decode
}
