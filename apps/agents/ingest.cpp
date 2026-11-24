// routeguard-ingest: reads BGP updates (MRT or bgpdump text) and maintains
// one slot per (peer, prefix) in the shared rg.routes table.
//
//   routeguard-ingest --mrt updates.mrt [--rate 100000] [--slots 1048576]
//   routeguard-ingest --create-only            # just create the table
//
// Crash-safe: on start it rebuilds its (peer, prefix) -> slot index by
// scanning the table, so a restarted ingest continues where it left off.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>

#include "agent_common.hpp"
#include "routeguard/bgp_update.hpp"
#include "routeguard/latency.hpp"
#include "routeguard/mrt.hpp"
#include "routeguard/pipeline.hpp"

namespace {

using rg::pipeline::RouteRecord;
using rg::state::SlotId;

struct Key {
  rg::Prefix prefix;
  std::uint32_t peer = 0;
  bool operator==(const Key&) const = default;
};

struct KeyHash {
  std::size_t operator()(const Key& k) const noexcept {
    return k.prefix.hash() ^ (std::size_t{k.peer} * 0x9E37'79B9'7F4A'7C15ULL);
  }
};

class Ingest {
 public:
  Ingest(rg::state::TableWriter& writer, double rate) : writer_(writer), rate_(rate) {}

  // Recovers the key -> slot index from whatever is already in the table.
  std::size_t rebuild(const std::string& table) {
    auto reader = rg::state::TableReader::open(table);
    RouteRecord rec;
    const auto n = static_cast<std::uint32_t>(reader.slot_count());
    free_.reserve(n);
    for (std::uint32_t s = n; s-- > 0;) {  // reverse, so low slots are handed out first
      const auto r = reader.read(SlotId{s}, rg::agent::writable_bytes_of(rec));
      if (r.status == rg::state::ReadResult::Status::Ok) {
        index_.emplace(Key{rec.prefix, rec.peer_asn}, s);
      } else {
        free_.push_back(s);
      }
    }
    return index_.size();
  }

  void handle(const rg::BgpUpdate& u) {
    pace();
    const Key key{u.prefix, u.peer_asn};
    if (u.kind == rg::UpdateKind::Withdraw) {
      ++withdrawals;
      const auto it = index_.find(key);
      if (it == index_.end()) return;
      writer_.erase(SlotId{it->second});
      free_.push_back(it->second);
      index_.erase(it);
      return;
    }

    ++announcements;
    std::uint32_t slot = 0;
    if (const auto it = index_.find(key); it != index_.end()) {
      slot = it->second;
    } else if (!free_.empty()) {
      slot = free_.back();
      free_.pop_back();
      index_.emplace(key, slot);
    } else {
      ++dropped;  // table full
      return;
    }

    RouteRecord rec;
    rec.prefix = u.prefix;
    rec.peer_asn = u.peer_asn;
    rec.origin = u.origin_asn().value_or(0);
    rec.origin_is_set = u.origin_is_set ? 1 : 0;
    rec.path_len = static_cast<std::uint32_t>(std::min(u.as_path.size(), rg::pipeline::kMaxPathLen));
    rec.path_truncated = u.as_path.size() > rg::pipeline::kMaxPathLen ? 1 : 0;
    std::copy_n(u.as_path.begin(), rec.path_len, rec.path);
    rec.bgp_time = u.timestamp;
    rec.ingest_ns = rg::now_ns();
    writer_.write(SlotId{slot}, rg::agent::bytes_of(rec));
  }

  std::size_t live_keys() const { return index_.size(); }

  std::uint64_t announcements = 0, withdrawals = 0, dropped = 0;

 private:
  // Optional fixed-rate replay, so latency can be measured at a known load
  // rather than only at saturation.
  void pace() {
    if (rate_ <= 0) return;
    if (sent_ == 0) start_ = std::chrono::steady_clock::now();
    const auto target = start_ + std::chrono::nanoseconds(static_cast<std::int64_t>(1e9 * static_cast<double>(sent_) / rate_));
    ++sent_;
    while (true) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= target) return;
      if (target - now > std::chrono::microseconds(200)) std::this_thread::sleep_for(target - now - std::chrono::microseconds(100));
    }
  }

  rg::state::TableWriter& writer_;
  double rate_;
  std::uint64_t sent_ = 0;
  std::chrono::steady_clock::time_point start_;
  std::unordered_map<Key, std::uint32_t, KeyHash> index_;
  std::vector<std::uint32_t> free_;
};

}  // namespace

int main(int argc, char** argv) {
  const rg::agent::Args args(argc, argv);
  if (args.has("-h") || args.has("--help")) {
    std::cerr << "usage: routeguard-ingest [--table rg.routes] [--slots N] [--ring N]\n"
                 "         (--mrt <file>|- | --updates <file>|-) [--rate updates_per_sec] | --create-only\n";
    return 0;
  }
  rg::agent::install_signal_handlers();

  const auto table = args.get("--table", rg::pipeline::kRoutesTable);
  const auto slots = static_cast<std::size_t>(args.get_int("--slots", 1 << 20));
  const auto ring = static_cast<std::size_t>(args.get_int("--ring", 1 << 20));

  try {
    auto writer = rg::state::TableWriter::open_or_create(table, slots, sizeof(RouteRecord), ring);
    if (writer.recovered_slots() > 0) {
      std::cerr << "ingest: repaired " << writer.recovered_slots() << " slots torn by a crashed writer\n";
    }
    if (args.has("--create-only")) {
      std::cerr << "ingest: created " << table << " (" << slots << " slots)\n";
      return 0;
    }

    Ingest ingest(writer, static_cast<double>(args.get_int("--rate", 0)));
    std::cerr << "ingest: rebuilt " << ingest.rebuild(table) << " keys from existing table\n";

    const bool mrt = args.has("--mrt");
    const auto path = mrt ? args.get("--mrt") : args.get("--updates", "-");
    std::ifstream file;
    std::istream* in = &std::cin;
    if (path != "-") {
      file.open(path, std::ios::binary);
      if (!file) {
        std::cerr << "ingest: cannot open " << path << '\n';
        return 1;
      }
      in = &file;
    }

    const auto t0 = std::chrono::steady_clock::now();
    if (mrt) {
      rg::MrtReader reader(*in);
      std::vector<rg::BgpUpdate> batch;
      while (!rg::agent::g_stop.load(std::memory_order_relaxed) && reader.next(batch)) {
        for (const auto& u : batch) ingest.handle(u);
        batch.clear();
      }
    } else {
      std::string line;
      while (!rg::agent::g_stop.load(std::memory_order_relaxed) && std::getline(*in, line)) {
        if (const auto u = rg::parse_bgpdump_line(line)) ingest.handle(*u);
      }
    }
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    const auto total = ingest.announcements + ingest.withdrawals;
    std::cerr << "ingest: " << total << " updates (" << ingest.announcements << " announce, " << ingest.withdrawals
              << " withdraw, " << ingest.dropped << " dropped) in " << secs << " s = "
              << static_cast<std::uint64_t>(static_cast<double>(total) / std::max(secs, 1e-9))
              << " updates/s; live keys " << ingest.live_keys() << '\n';
  } catch (const std::exception& e) {
    std::cerr << "ingest: " << e.what() << '\n';
    return 1;
  }
  return 0;
}
