#include "routeguard/rpki.hpp"

#include <string>

#include "text_util.hpp"

namespace rg {

std::string_view to_string(RovState s) noexcept {
  switch (s) {
    case RovState::Valid: return "VALID";
    case RovState::Invalid: return "INVALID";
    case RovState::NotFound: return "NOT_FOUND";
  }
  return "?";
}

bool RoaTable::add(const Roa& roa) {
  if (roa.max_length < roa.prefix.length() || roa.max_length > roa.prefix.max_length()) return false;
  trie_for(roa.prefix.family()).insert_or_get(roa.prefix).push_back(roa);
  ++count_;
  return true;
}

// RFC 6811 section 2:
//   * A ROA "covers" the route if the ROA prefix covers the route prefix.
//   * A covering ROA "matches" if its ASN equals the route's origin AS and the
//     route length is <= the ROA max length. AS0 never matches (RFC 6483).
//   * Matched -> Valid; covered but not matched -> Invalid; else NotFound.
RovState RoaTable::validate(const Prefix& route, std::uint32_t origin) const {
  bool covered = false;
  bool matched = false;
  trie_for(route.family()).for_each_covering(route, [&](const Prefix&, const std::vector<Roa>& roas) {
    for (const Roa& roa : roas) {
      covered = true;
      if (origin != 0 && roa.asn == origin && route.length() <= roa.max_length) matched = true;
    }
  });
  if (matched) return RovState::Valid;
  return covered ? RovState::Invalid : RovState::NotFound;
}

CsvLoadStats load_roas_csv(std::istream& in, RoaTable& table) {
  CsvLoadStats parsed;
  CsvLoadStats stats;
  for (const Roa& roa : parse_roas_csv(in, parsed)) {
    if (table.add(roa)) {
      ++stats.loaded;
    } else {
      ++stats.skipped;
    }
  }
  stats.skipped += parsed.skipped;
  return stats;
}

std::vector<Roa> parse_roas_csv(std::istream& in, CsvLoadStats& stats) {
  std::vector<Roa> roas;
  std::string raw;
  while (std::getline(in, raw)) {
    const auto line = detail::trim(raw);
    if (line.empty() || line.front() == '#') continue;

    const auto fields = detail::split(line, ',');
    if (fields.size() < 3) {
      ++stats.skipped;
      continue;
    }
    const auto asn = detail::parse_asn(detail::trim(fields[0]));
    const auto prefix = Prefix::parse(fields[1]);
    const auto max_len = detail::parse_int<int>(detail::trim(fields[2]));
    if (!asn || !prefix || !max_len) {
      // The header row ("ASN,IP Prefix,Max Length,...") lands here too; that
      // is fine, but don't count it as a skipped record.
      if (detail::trim(fields[0]) != "ASN") ++stats.skipped;
      continue;
    }
    roas.push_back(Roa{*prefix, *max_len, *asn});
    ++stats.loaded;
  }
  return roas;
}

}  // namespace rg
