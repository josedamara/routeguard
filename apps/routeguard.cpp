// routeguard: validate a stream of BGP updates against an RPKI VRP table.
//
//   routeguard --roas vrps.csv --updates updates.txt
//   bgpdump -m updates.20261117.0000.gz | routeguard --roas vrps.csv
//
// Prints RPKI-invalid announcements to stdout (all results with --all) and a
// summary to stderr.

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

#include "routeguard/bgp_update.hpp"
#include "routeguard/rpki.hpp"

namespace {

void usage(const char* argv0) {
  std::cerr << "usage: " << argv0 << " --roas <vrps.csv> [--updates <file>|-] [--all]\n"
            << "  --roas     VRP CSV (Routinator / rpki-client format)\n"
            << "  --updates  bgpdump -m formatted updates; '-' or omitted = stdin\n"
            << "  --all      print every validated announcement, not only invalid ones\n";
}

std::string format_path(const rg::BgpUpdate& u) {
  std::string out;
  for (const auto asn : u.as_path) {
    if (!out.empty()) out += ' ';
    out += std::to_string(asn);
  }
  if (u.origin_is_set) out += " {AS_SET}";
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  std::string roas_path;
  std::string updates_path = "-";
  bool show_all = false;

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--roas" && i + 1 < argc) {
      roas_path = argv[++i];
    } else if (arg == "--updates" && i + 1 < argc) {
      updates_path = argv[++i];
    } else if (arg == "--all") {
      show_all = true;
    } else if (arg == "-h" || arg == "--help") {
      usage(argv[0]);
      return 0;
    } else {
      usage(argv[0]);
      return 2;
    }
  }
  if (roas_path.empty()) {
    usage(argv[0]);
    return 2;
  }

  std::ifstream roa_file(roas_path);
  if (!roa_file) {
    std::cerr << "error: cannot open " << roas_path << '\n';
    return 1;
  }
  rg::RoaTable table;
  const auto stats = rg::load_roas_csv(roa_file, table);
  std::cerr << "loaded " << stats.loaded << " VRPs (" << stats.skipped << " skipped)\n";

  std::ifstream updates_file;
  std::istream* in = &std::cin;
  if (updates_path != "-") {
    updates_file.open(updates_path);
    if (!updates_file) {
      std::cerr << "error: cannot open " << updates_path << '\n';
      return 1;
    }
    in = &updates_file;
  }

  std::uint64_t valid = 0, invalid = 0, not_found = 0, withdrawn = 0, malformed = 0;
  std::string line;
  while (std::getline(*in, line)) {
    if (line.empty()) continue;
    const auto update = rg::parse_bgpdump_line(line);
    if (!update) {
      ++malformed;
      continue;
    }
    if (update->kind == rg::UpdateKind::Withdraw) {
      ++withdrawn;
      continue;
    }

    const auto origin = update->origin_asn();
    const auto state = table.validate(update->prefix, origin.value_or(0));
    switch (state) {
      case rg::RovState::Valid: ++valid; break;
      case rg::RovState::Invalid: ++invalid; break;
      case rg::RovState::NotFound: ++not_found; break;
    }

    if (show_all || state == rg::RovState::Invalid) {
      std::cout << rg::to_string(state) << '\t' << update->prefix.to_string() << "\torigin="
                << (origin ? "AS" + std::to_string(*origin) : std::string("none")) << "\tpeer=AS"
                << update->peer_asn << "\tpath=" << format_path(*update) << '\n';
    }
  }

  std::cerr << "announcements: valid=" << valid << " invalid=" << invalid << " not_found=" << not_found
            << " | withdrawals=" << withdrawn << " malformed=" << malformed << '\n';
  return 0;
}
