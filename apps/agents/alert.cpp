// routeguard-alert: watches rg.verdicts and reports routes that fail ROV or
// ASPA, plus end-to-end latency from ingest to alert across all three
// processes.
//
//   routeguard-alert [--quiet] [--exit-when-idle-ms N]

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "agent_common.hpp"
#include "routeguard/latency.hpp"
#include "routeguard/pipeline.hpp"

namespace {

using rg::pipeline::VerdictRecord;
using rg::state::ReadResult;
using rg::state::SlotId;

}  // namespace

int main(int argc, char** argv) {
  std::ios::sync_with_stdio(false);
  const rg::agent::Args args(argc, argv);
  if (args.has("-h") || args.has("--help")) {
    std::cerr << "usage: routeguard-alert [--in rg.verdicts] [--quiet] [--exit-when-idle-ms N]\n";
    return 0;
  }
  rg::agent::install_signal_handlers();
  const bool quiet = args.has("--quiet");
  const auto idle_exit = std::chrono::milliseconds(args.get_int("--exit-when-idle-ms", 0));

  try {
    auto verdicts = rg::agent::open_reader_with_retry(args.get("--in", rg::pipeline::kVerdictsTable));
    std::cerr << "alert: ready\n";

    rg::LatencyRecorder e2e(1U << 22);
    std::uint64_t seen = 0, rov_invalid = 0, aspa_invalid = 0, resyncs = 0;
    std::vector<SlotId> changes(8192);
    auto last_activity = std::chrono::steady_clock::now();
    bool seen_any = false;

    while (!rg::agent::g_stop.load(std::memory_order_relaxed)) {
      if (!verdicts.wait_for_changes(std::chrono::milliseconds(50))) {
        if (idle_exit.count() > 0 && seen_any && std::chrono::steady_clock::now() - last_activity > idle_exit) break;
        continue;
      }
      seen_any = true;
      last_activity = std::chrono::steady_clock::now();
      const auto c = verdicts.drain_changes(changes);
      if (c.overflowed) ++resyncs;  // missed some intermediate verdicts; latest state still readable
      for (std::size_t i = 0; i < c.count; ++i) {
        VerdictRecord v;
        if (verdicts.read(changes[i], rg::agent::writable_bytes_of(v)).status != ReadResult::Status::Ok) continue;
        const auto now = rg::now_ns();
        e2e.add(now - v.ingest_ns);
        ++seen;
        const bool bad_rov = v.rov == rg::RovState::Invalid;
        const bool bad_aspa = v.aspa == rg::AspaState::Invalid;
        rov_invalid += bad_rov ? 1 : 0;
        aspa_invalid += bad_aspa ? 1 : 0;
        if (!quiet && (bad_rov || bad_aspa)) {
          std::cout << "rov=" << rg::to_string(v.rov) << "\taspa=" << rg::to_string(v.aspa) << '\t'
                    << v.prefix.to_string() << "\torigin="
                    << (v.origin != 0 ? "AS" + std::to_string(v.origin) : std::string("none")) << "\tpeer=AS"
                    << v.peer_asn << "\tlatency_us=" << (now - v.ingest_ns) / 1000 << '\n';
        }
      }
    }
    std::cout.flush();
    std::cerr << "alert: verdicts=" << seen << " rov_invalid=" << rov_invalid << " aspa_invalid=" << aspa_invalid
              << " resyncs=" << resyncs << '\n'
              << "alert: end-to-end latency (ingest -> alert) " << rg::LatencyRecorder::format(e2e.summarize())
              << '\n';
  } catch (const std::exception& e) {
    std::cerr << "alert: " << e.what() << '\n';
    return 1;
  }
  return 0;
}
