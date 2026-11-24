// routeguard-validator: watches rg.routes, runs RPKI ROV and ASPA on every
// changed route and publishes the result to rg.verdicts (same slot index).
//
//   routeguard-validator --vrps data/vrps.csv [--aspas data/aspas.csv]
//                        [--aspa-mode downstream|upstream] [--exit-when-idle-ms N]
//
// Crash-safe: on start (and whenever it falls too far behind the change
// ring) it rescans every slot, so a restarted validator converges.

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <span>
#include <vector>

#include "agent_common.hpp"
#include "routeguard/aspa.hpp"
#include "routeguard/latency.hpp"
#include "routeguard/pipeline.hpp"
#include "routeguard/rpki.hpp"

namespace {

using rg::pipeline::RouteRecord;
using rg::pipeline::VerdictRecord;
using rg::state::ReadResult;
using rg::state::SlotId;

class Validator {
 public:
  Validator(rg::state::TableReader& routes, rg::state::TableWriter& verdicts, const std::string& verdicts_name,
            const rg::RoaTable& roas, const rg::AspaTable* aspas, rg::AspaDirection dir)
      : routes_(routes), verdicts_(verdicts), roas_(roas), aspas_(aspas), dir_(dir) {
    // Learn which verdict slots are populated (non-empty after a restart) so
    // a full scan only erases slots that actually hold something.
    present_.assign(routes.slot_count(), 0);
    auto existing = rg::state::TableReader::open(verdicts_name);
    VerdictRecord v;
    for (std::uint32_t s = 0; s < present_.size(); ++s) {
      if (existing.read(SlotId{s}, rg::agent::writable_bytes_of(v)).status == ReadResult::Status::Ok) present_[s] = 1;
    }
  }

  // record_latency is false during full scans: those routes may have been
  // ingested long before this validator started.
  void process(std::uint32_t slot, bool record_latency = true) {
    RouteRecord route;
    const auto r = routes_.read(SlotId{slot}, rg::agent::writable_bytes_of(route));
    if (r.status == ReadResult::Status::Busy) {
      ++busy;  // writer died mid-write; its restart will republish the slot
      return;
    }
    if (r.status == ReadResult::Status::Empty) {
      if (present_[slot] != 0) {
        verdicts_.erase(SlotId{slot});
        present_[slot] = 0;
      }
      return;
    }

    VerdictRecord v;
    v.prefix = route.prefix;
    v.peer_asn = route.peer_asn;
    v.origin = route.origin;
    v.rov = roas_.validate(route.prefix, route.origin);
    if (aspas_ != nullptr) {
      v.aspa = route.path_truncated != 0
                   ? rg::AspaState::Unknown
                   : aspas_->verify(std::span(route.path, route.path_len), dir_, route.origin_is_set != 0);
    }
    v.ingest_ns = route.ingest_ns;
    v.validated_ns = rg::now_ns();
    verdicts_.write(SlotId{slot}, rg::agent::bytes_of(v));
    present_[slot] = 1;
    ++validated;
    if (record_latency) stage_latency.add(v.validated_ns - route.ingest_ns);
  }

  void full_scan() {
    for (std::uint32_t s = 0; s < present_.size(); ++s) process(s, false);
  }

  std::uint64_t validated = 0, busy = 0, resyncs = 0;
  rg::LatencyRecorder stage_latency{1U << 22};

 private:
  rg::state::TableReader& routes_;
  rg::state::TableWriter& verdicts_;
  const rg::RoaTable& roas_;
  const rg::AspaTable* aspas_;
  rg::AspaDirection dir_;
  std::vector<std::uint8_t> present_;
};

}  // namespace

int main(int argc, char** argv) {
  const rg::agent::Args args(argc, argv);
  if (args.has("-h") || args.has("--help") || !args.has("--vrps")) {
    std::cerr << "usage: routeguard-validator --vrps <vrps.csv> [--aspas <aspas.csv>]\n"
                 "         [--aspa-mode downstream|upstream] [--in rg.routes] [--out rg.verdicts]\n"
                 "         [--ring N] [--exit-when-idle-ms N]\n";
    return args.has("--vrps") ? 0 : 2;
  }
  rg::agent::install_signal_handlers();

  rg::RoaTable roas;
  {
    std::ifstream f(args.get("--vrps"));
    if (!f) {
      std::cerr << "validator: cannot open " << args.get("--vrps") << '\n';
      return 1;
    }
    const auto s = rg::load_roas_csv(f, roas);
    std::cerr << "validator: loaded " << s.loaded << " VRPs\n";
  }
  rg::AspaTable aspas;
  const bool use_aspa = args.has("--aspas");
  if (use_aspa) {
    std::ifstream f(args.get("--aspas"));
    if (!f) {
      std::cerr << "validator: cannot open " << args.get("--aspas") << '\n';
      return 1;
    }
    const auto s = rg::load_aspa_csv(f, aspas);
    std::cerr << "validator: loaded " << s.loaded << " ASPAs\n";
  }
  const auto dir = args.get("--aspa-mode", "downstream") == "upstream" ? rg::AspaDirection::Upstream
                                                                       : rg::AspaDirection::Downstream;
  const auto idle_exit = std::chrono::milliseconds(args.get_int("--exit-when-idle-ms", 0));

  try {
    auto routes = rg::agent::open_reader_with_retry(args.get("--in", rg::pipeline::kRoutesTable));
    const auto out_name = args.get("--out", rg::pipeline::kVerdictsTable);
    auto verdicts = rg::state::TableWriter::open_or_create(out_name, routes.slot_count(), sizeof(VerdictRecord),
                                                           static_cast<std::size_t>(args.get_int("--ring", 1 << 20)));
    Validator v(routes, verdicts, out_name, roas, use_aspa ? &aspas : nullptr, dir);
    v.full_scan();
    std::cerr << "validator: ready (" << routes.slot_count() << " slots, initial scan validated " << v.validated
              << ")\n";

    std::vector<SlotId> changes(8192);
    auto last_activity = std::chrono::steady_clock::now();
    bool seen_any = false;
    while (!rg::agent::g_stop.load(std::memory_order_relaxed)) {
      if (!routes.wait_for_changes(std::chrono::milliseconds(50))) {
        if (idle_exit.count() > 0 && seen_any && std::chrono::steady_clock::now() - last_activity > idle_exit) break;
        continue;
      }
      seen_any = true;
      last_activity = std::chrono::steady_clock::now();
      const auto c = routes.drain_changes(changes);
      for (std::size_t i = 0; i < c.count; ++i) v.process(changes[i].value);
      if (c.overflowed) {
        ++v.resyncs;
        v.full_scan();
      }
    }
    std::cerr << "validator: validated=" << v.validated << " resyncs=" << v.resyncs << " busy=" << v.busy << '\n'
              << "validator: stage latency (ingest -> validated) "
              << rg::LatencyRecorder::format(v.stage_latency.summarize()) << '\n';
  } catch (const std::exception& e) {
    std::cerr << "validator: " << e.what() << '\n';
    return 1;
  }
  return 0;
}
