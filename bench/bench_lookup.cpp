// bench_lookup: single-threaded throughput and latency of every stage of the
// validation path, measured on real data.
//
//   bench_lookup --vrps data/vrps.csv --aspas data/aspas.csv --mrt updates.mrt
//
// Reports:
//   1. MRT decode throughput (MB/s, prefixes/s)
//   2. Binary trie vs Patricia trie: build time, nodes, memory, LPM ns/lookup
//   3. RFC 6811 ROV and ASPA verification: throughput + per-call percentiles
//   4. Whole single-process pipeline: decode + ROV + ASPA, updates/s

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

#include "routeguard/aspa.hpp"
#include "routeguard/latency.hpp"
#include "routeguard/mrt.hpp"
#include "routeguard/patricia_trie.hpp"
#include "routeguard/prefix_trie.hpp"
#include "routeguard/rpki.hpp"

namespace {

using Clock = std::chrono::steady_clock;

double seconds_since(Clock::time_point t0) { return std::chrono::duration<double>(Clock::now() - t0).count(); }

std::string arg(int argc, char** argv, const std::string& flag) {
  for (int i = 1; i + 1 < argc; ++i)
    if (flag == argv[i]) return argv[i + 1];
  return {};
}

// Compact announcement: what validation needs, without per-update heap use.
struct Query {
  rg::Prefix prefix;
  std::uint32_t origin;
  std::uint32_t path_offset;
  std::uint16_t path_len;
  bool as_set;
};

std::vector<std::uint8_t> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open " + path);
  return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

// Measures the cost of one now_ns() call so per-call percentiles can be read
// with that overhead in mind.
std::uint64_t timer_overhead_ns() {
  rg::LatencyRecorder r(100000);
  for (int i = 0; i < 100000; ++i) {
    const auto a = rg::now_ns();
    const auto b = rg::now_ns();
    r.add(b - a);
  }
  return r.summarize().p50;
}

template <typename Trie>
void bench_trie(const char* name, const std::vector<rg::Roa>& roas, const std::vector<Query>& queries) {
  Trie v4, v6;
  const auto t0 = Clock::now();
  for (const auto& roa : roas) {
    (roa.prefix.family() == rg::Family::V4 ? v4 : v6).insert_or_get(roa.prefix) += 1;
  }
  const double build_s = seconds_since(t0);
  const auto nodes = v4.node_count() + v6.node_count();
  const double mem_mb = static_cast<double>(v4.memory_bytes() + v6.memory_bytes()) / (1024.0 * 1024.0);

  double best_ns = 1e18;
  std::uint64_t sink = 0;
  for (int run = 0; run < 3; ++run) {
    const auto t1 = Clock::now();
    for (const auto& q : queries) {
      const auto* hit = (q.prefix.family() == rg::Family::V4 ? v4 : v6).longest_match(q.prefix);
      sink += hit != nullptr ? static_cast<std::uint64_t>(*hit) : 0;
    }
    best_ns = std::min(best_ns, seconds_since(t1) * 1e9 / static_cast<double>(queries.size()));
  }
  std::printf("  %-8s build=%.0f ms  nodes=%zu  memory=%.1f MiB  LPM=%.1f ns/lookup (%.2f M lookups/s)  [chk %llu]\n",
              name, build_s * 1e3, nodes, mem_mb, best_ns, 1e3 / best_ns, static_cast<unsigned long long>(sink % 10));
}

}  // namespace

int main(int argc, char** argv) {
  const auto vrps_path = arg(argc, argv, "--vrps");
  const auto aspas_path = arg(argc, argv, "--aspas");
  const auto mrt_path = arg(argc, argv, "--mrt");
  if (vrps_path.empty() || aspas_path.empty() || mrt_path.empty()) {
    std::cerr << "usage: bench_lookup --vrps <csv> --aspas <csv> --mrt <file>\n";
    return 2;
  }

  // ---------------------------------------------------------------- data --
  std::vector<rg::Roa> roas;
  {
    std::ifstream f(vrps_path);
    rg::CsvLoadStats s;
    roas = rg::parse_roas_csv(f, s);
  }
  rg::AspaTable aspas;
  {
    std::ifstream f(aspas_path);
    rg::load_aspa_csv(f, aspas);
  }
  const auto mrt = read_file(mrt_path);
  std::printf("data: %zu VRPs, %zu ASPAs, %.1f MiB of MRT\n", roas.size(), aspas.size(),
              static_cast<double>(mrt.size()) / (1024.0 * 1024.0));

  // ------------------------------------------------------- 1. MRT decode --
  {
    rg::MrtStats stats;
    std::vector<rg::BgpUpdate> out;
    out.reserve(1 << 16);
    const auto t0 = Clock::now();
    std::size_t pos = 0;
    while (pos < mrt.size()) {  // decode record by record, reusing the output buffer
      const auto used = rg::decode_mrt_buffer(std::span(mrt).subspan(pos, std::min<std::size_t>(mrt.size() - pos, 1 << 20)), out, &stats);
      if (used == 0) break;
      pos += used;
      out.clear();
    }
    const double s = seconds_since(t0);
    std::printf("\n[1] MRT decode: %llu records, %llu prefix updates, %llu malformed in %.2f s\n"
                "    %.0f MiB/s, %.2f M prefix updates/s\n",
                static_cast<unsigned long long>(stats.records), static_cast<unsigned long long>(stats.prefixes),
                static_cast<unsigned long long>(stats.malformed), s,
                static_cast<double>(stats.bytes) / (1024.0 * 1024.0) / s, static_cast<double>(stats.prefixes) / s / 1e6);
  }

  // Build the compact query set (untimed).
  std::vector<Query> queries;
  std::vector<std::uint32_t> paths;
  {
    std::vector<rg::BgpUpdate> all;
    rg::decode_mrt_buffer(mrt, all);
    for (const auto& u : all) {
      if (u.kind != rg::UpdateKind::Announce) continue;
      queries.push_back(Query{u.prefix, u.origin_asn().value_or(0), static_cast<std::uint32_t>(paths.size()),
                              static_cast<std::uint16_t>(u.as_path.size()), u.origin_is_set});
      paths.insert(paths.end(), u.as_path.begin(), u.as_path.end());
    }
  }
  std::printf("    %zu announcements used as lookup queries\n", queries.size());

  // ------------------------------------------------- 2. trie comparison --
  std::printf("\n[2] Prefix index over all VRP prefixes (IPv4 + IPv6)\n");
  bench_trie<rg::PrefixTrie<std::uint32_t>>("binary", roas, queries);
  bench_trie<rg::PatriciaTrie<std::uint32_t>>("patricia", roas, queries);

  // ------------------------------------------------ 3. ROV and ASPA -------
  rg::RoaTable table;
  {
    const auto t0 = Clock::now();
    for (const auto& r : roas) table.add(r);
    std::printf("\n[3] RoaTable (binary trie) built in %.0f ms\n", seconds_since(t0) * 1e3);
  }
  const auto overhead = timer_overhead_ns();
  std::printf("    timer overhead (now_ns pair) p50 = %llu ns, included in per-call numbers below\n",
              static_cast<unsigned long long>(overhead));

  {
    std::uint64_t counts[3] = {};
    const auto t0 = Clock::now();
    for (const auto& q : queries) ++counts[static_cast<int>(table.validate(q.prefix, q.origin))];
    const double s = seconds_since(t0);
    rg::LatencyRecorder lat(queries.size());
    for (const auto& q : queries) {
      const auto a = rg::now_ns();
      ++counts[static_cast<int>(table.validate(q.prefix, q.origin))];
      lat.add(rg::now_ns() - a);
    }
    std::printf("    ROV:  %.2f M validations/s (%.0f ns avg)  per-call %s\n",
                static_cast<double>(queries.size()) / s / 1e6, s * 1e9 / static_cast<double>(queries.size()),
                rg::LatencyRecorder::format(lat.summarize(), 1.0, "ns").c_str());
    std::printf("          valid=%llu invalid=%llu not_found=%llu\n", static_cast<unsigned long long>(counts[0] / 2),
                static_cast<unsigned long long>(counts[1] / 2), static_cast<unsigned long long>(counts[2] / 2));
  }
  {
    std::uint64_t counts[3] = {};
    auto path_of = [&](const Query& q) { return std::span(paths).subspan(q.path_offset, q.path_len); };
    const auto t0 = Clock::now();
    for (const auto& q : queries) {
      ++counts[static_cast<int>(aspas.verify(path_of(q), rg::AspaDirection::Downstream, q.as_set))];
    }
    const double s = seconds_since(t0);
    rg::LatencyRecorder lat(queries.size());
    for (const auto& q : queries) {
      const auto a = rg::now_ns();
      ++counts[static_cast<int>(aspas.verify(path_of(q), rg::AspaDirection::Downstream, q.as_set))];
      lat.add(rg::now_ns() - a);
    }
    std::printf("    ASPA: %.2f M verifications/s (%.0f ns avg)  per-call %s\n",
                static_cast<double>(queries.size()) / s / 1e6, s * 1e9 / static_cast<double>(queries.size()),
                rg::LatencyRecorder::format(lat.summarize(), 1.0, "ns").c_str());
    std::printf("          valid=%llu invalid=%llu unknown=%llu\n", static_cast<unsigned long long>(counts[0] / 2),
                static_cast<unsigned long long>(counts[1] / 2), static_cast<unsigned long long>(counts[2] / 2));
  }

  // --------------------------------------- 4. single-process end to end --
  {
    std::uint64_t n = 0, bad = 0;
    std::vector<rg::BgpUpdate> out;
    const auto t0 = Clock::now();
    std::size_t pos = 0;
    while (pos < mrt.size()) {
      const auto used = rg::decode_mrt_buffer(std::span(mrt).subspan(pos, std::min<std::size_t>(mrt.size() - pos, 1 << 20)), out);
      if (used == 0) break;
      pos += used;
      for (const auto& u : out) {
        ++n;
        if (u.kind != rg::UpdateKind::Announce) continue;
        const auto rov = table.validate(u.prefix, u.origin_asn().value_or(0));
        const auto aspa = aspas.verify(u.as_path, rg::AspaDirection::Downstream, u.origin_is_set);
        bad += (rov == rg::RovState::Invalid || aspa == rg::AspaState::Invalid) ? 1 : 0;
      }
      out.clear();
    }
    const double s = seconds_since(t0);
    std::printf("\n[4] decode + ROV + ASPA, one thread: %llu updates in %.2f s = %.2f M updates/s (%llu flagged)\n",
                static_cast<unsigned long long>(n), s, static_cast<double>(n) / s / 1e6,
                static_cast<unsigned long long>(bad));
  }
  return 0;
}
