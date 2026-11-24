// routeguard: validate a stream of BGP updates against RPKI (ROV + ASPA).
//
//   routeguard --roas vrps.csv --updates updates.txt          # bgpdump -m text
//   gunzip -c updates.*.gz | routeguard --roas vrps.csv --aspas aspas.csv --mrt -
//
// Prints announcements that fail ROV or ASPA to stdout (everything with
// --all) and a summary to stderr.

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

#include "routeguard/aspa.hpp"
#include "routeguard/bgp_update.hpp"
#include "routeguard/mrt.hpp"
#include "routeguard/rpki.hpp"

namespace {

void usage(const char* argv0) {
  std::cerr << "usage: " << argv0
            << " --roas <vrps.csv> [--aspas <aspas.csv>] [--aspa-mode downstream|upstream]\n"
            << "       [--updates <file>|- | --mrt <file>|-] [--all]\n"
            << "  --roas       VRP CSV (Routinator / rpki-client format)\n"
            << "  --aspas      ASPA CSV written by scripts/fetch_vrps.py (enables path checks)\n"
            << "  --aspa-mode  treat routes as received from a provider (downstream, default)\n"
            << "               or from a customer/peer (upstream)\n"
            << "  --updates    bgpdump -m text; '-' = stdin (default)\n"
            << "  --mrt        raw MRT BGP4MP records, e.g. gunzip -c updates.*.gz\n"
            << "  --all        print every announcement, not only failing ones\n";
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

struct Counters {
  std::uint64_t rov[3] = {};
  std::uint64_t aspa[3] = {};
  std::uint64_t withdrawn = 0;
  std::uint64_t malformed = 0;
};

class Validator {
 public:
  Validator(const rg::RoaTable& roas, const rg::AspaTable* aspas, rg::AspaDirection dir, bool show_all)
      : roas_(roas), aspas_(aspas), dir_(dir), show_all_(show_all) {}

  void process(const rg::BgpUpdate& u) {
    if (u.kind == rg::UpdateKind::Withdraw) {
      ++c.withdrawn;
      return;
    }
    const auto origin = u.origin_asn();
    const auto rov = roas_.validate(u.prefix, origin.value_or(0));
    ++c.rov[static_cast<int>(rov)];

    auto aspa = rg::AspaState::Unknown;
    if (aspas_ != nullptr) {
      aspa = aspas_->verify(u.as_path, dir_, u.origin_is_set);
      ++c.aspa[static_cast<int>(aspa)];
    }

    if (show_all_ || rov == rg::RovState::Invalid || aspa == rg::AspaState::Invalid) {
      std::cout << "rov=" << rg::to_string(rov);
      if (aspas_ != nullptr) std::cout << "\taspa=" << rg::to_string(aspa);
      std::cout << '\t' << u.prefix.to_string() << "\torigin="
                << (origin ? "AS" + std::to_string(*origin) : std::string("none")) << "\tpeer=AS"
                << u.peer_asn << "\tpath=" << format_path(u) << '\n';
    }
  }

  Counters c;

 private:
  const rg::RoaTable& roas_;
  const rg::AspaTable* aspas_;
  rg::AspaDirection dir_;
  bool show_all_;
};

}  // namespace

int main(int argc, char** argv) {
  std::ios::sync_with_stdio(false);
  std::string roas_path, aspas_path, input = "-";
  bool mrt = false, show_all = false;
  auto direction = rg::AspaDirection::Downstream;

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    const bool has_value = i + 1 < argc;
    if (arg == "--roas" && has_value) {
      roas_path = argv[++i];
    } else if (arg == "--aspas" && has_value) {
      aspas_path = argv[++i];
    } else if (arg == "--aspa-mode" && has_value) {
      const std::string_view mode = argv[++i];
      if (mode == "upstream") {
        direction = rg::AspaDirection::Upstream;
      } else if (mode != "downstream") {
        usage(argv[0]);
        return 2;
      }
    } else if (arg == "--updates" && has_value) {
      input = argv[++i];
      mrt = false;
    } else if (arg == "--mrt" && has_value) {
      input = argv[++i];
      mrt = true;
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

  rg::RoaTable roas;
  {
    std::ifstream f(roas_path);
    if (!f) {
      std::cerr << "error: cannot open " << roas_path << '\n';
      return 1;
    }
    const auto s = rg::load_roas_csv(f, roas);
    std::cerr << "loaded " << s.loaded << " VRPs (" << s.skipped << " skipped)\n";
  }
  rg::AspaTable aspas;
  if (!aspas_path.empty()) {
    std::ifstream f(aspas_path);
    if (!f) {
      std::cerr << "error: cannot open " << aspas_path << '\n';
      return 1;
    }
    const auto s = rg::load_aspa_csv(f, aspas);
    std::cerr << "loaded " << s.loaded << " ASPAs (" << s.skipped << " skipped)\n";
  }

  std::ifstream file;
  std::istream* in = &std::cin;
  if (input != "-") {
    file.open(input, std::ios::binary);
    if (!file) {
      std::cerr << "error: cannot open " << input << '\n';
      return 1;
    }
    in = &file;
  }

  Validator v(roas, aspas_path.empty() ? nullptr : &aspas, direction, show_all);
  if (mrt) {
    rg::MrtReader reader(*in);
    std::vector<rg::BgpUpdate> batch;
    while (reader.next(batch)) {
      for (const auto& u : batch) v.process(u);
      batch.clear();
    }
    v.c.malformed = reader.stats().malformed;
  } else {
    std::string line;
    while (std::getline(*in, line)) {
      if (line.empty()) continue;
      const auto u = rg::parse_bgpdump_line(line);
      if (!u) {
        ++v.c.malformed;
        continue;
      }
      v.process(*u);
    }
  }

  const auto& c = v.c;
  std::cerr << "rov: valid=" << c.rov[0] << " invalid=" << c.rov[1] << " not_found=" << c.rov[2];
  if (!aspas_path.empty()) {
    std::cerr << " | aspa: valid=" << c.aspa[0] << " invalid=" << c.aspa[1] << " unknown=" << c.aspa[2];
  }
  std::cerr << " | withdrawals=" << c.withdrawn << " malformed=" << c.malformed << '\n';
  return 0;
}
