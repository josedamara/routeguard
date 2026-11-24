#include "routeguard/bgp_update.hpp"

#include "text_util.hpp"

namespace rg {

std::optional<std::uint32_t> BgpUpdate::origin_asn() const {
  if (kind == UpdateKind::Withdraw || as_path.empty() || origin_is_set) return std::nullopt;
  return as_path.back();
}

std::optional<BgpUpdate> parse_bgpdump_line(std::string_view line) {
  const auto f = detail::split(detail::trim(line), '|');
  // Fields: 0 type, 1 time, 2 A/W/B, 3 peer ip, 4 peer asn, 5 prefix, 6 path
  if (f.size() < 6) return std::nullopt;

  BgpUpdate u;
  if (f[2] == "A" || f[2] == "B") {
    u.kind = UpdateKind::Announce;
  } else if (f[2] == "W") {
    u.kind = UpdateKind::Withdraw;
  } else {
    return std::nullopt;  // STATE messages etc.
  }

  const auto ts = detail::parse_int<std::int64_t>(f[1]);
  const auto peer_asn = detail::parse_asn(f[4]);
  const auto prefix = Prefix::parse(f[5]);
  if (!ts || !peer_asn || !prefix) return std::nullopt;
  u.timestamp = *ts;
  u.peer_ip = std::string(f[3]);
  u.peer_asn = *peer_asn;
  u.prefix = *prefix;

  if (u.kind == UpdateKind::Withdraw) return u;
  if (f.size() < 7) return std::nullopt;

  for (const auto token : detail::split(f[6], ' ')) {
    if (token.empty()) continue;
    if (token.front() == '{') {  // AS_SET, e.g. "{64512,64513}"
      u.origin_is_set = true;
      continue;
    }
    const auto asn = detail::parse_asn(token);
    if (!asn) return std::nullopt;
    u.as_path.push_back(*asn);
    u.origin_is_set = false;  // a sequence hop after the set means the set wasn't last
  }
  return u;
}

}  // namespace rg
