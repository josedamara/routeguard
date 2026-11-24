// bench_store: latency and throughput of the shared-memory state store.
//
//   bench_store [--iters 200000]
//
// 1. Cross-process ping-pong. Process A writes slot "ping", process B wakes,
//    reads it and writes "pong", A wakes and reads it. One-way latency =
//    round trip / 2. Three reader strategies: futex only (idle readers use
//    no CPU), busy-poll (lowest latency, burns a core) and the default
//    spin-then-park (spin 50 us, then sleep on the futex).
// 2. Single-process write and read throughput with route-sized records.

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include "routeguard/latency.hpp"
#include "routeguard/pipeline.hpp"
#include "routeguard/state/state_store.hpp"

namespace {

using rg::state::ReadResult;
using rg::state::SlotId;
using rg::state::TableReader;
using rg::state::TableWriter;

constexpr std::uint64_t kStop = ~std::uint64_t{0};

std::span<const std::byte> bytes_of(const std::uint64_t& v) { return std::as_bytes(std::span<const std::uint64_t, 1>(&v, 1)); }

TableReader open_retry(const std::string& name) {
  for (int i = 0;; ++i) {
    try {
      return TableReader::open(name);
    } catch (...) {
      if (i > 5000) throw;
      std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
  }
}

enum class Mode { Futex, BusyPoll, SpinThenPark };

const char* mode_name(Mode m) {
  switch (m) {
    case Mode::Futex: return "futex-only";
    case Mode::BusyPoll: return "busy-poll";
    case Mode::SpinThenPark: return "spin-then-park";
  }
  return "?";
}

// Waits for the next change on `r` and returns the value in slot 0.
std::uint64_t receive(TableReader& r, Mode mode) {
  std::array<SlotId, 64> changes{};
  while (true) {
    switch (mode) {
      case Mode::BusyPoll:
        while (!r.has_changes()) {
        }
        break;
      case Mode::Futex: r.wait_for_changes(std::chrono::seconds(5), std::chrono::nanoseconds(0)); break;
      case Mode::SpinThenPark: r.wait_for_changes(std::chrono::seconds(5)); break;
    }
    if (r.drain_changes(changes).count > 0) break;
  }
  std::uint64_t v = 0;
  r.read(SlotId{0}, std::as_writable_bytes(std::span<std::uint64_t, 1>(&v, 1)));
  return v;
}

void ping_pong(Mode spin, std::uint64_t iters) {
  const std::string ping = "/rgbench.ping." + std::to_string(getpid());
  const std::string pong = "/rgbench.pong." + std::to_string(getpid());
  TableWriter::unlink(ping);
  TableWriter::unlink(pong);
  auto ping_w = TableWriter::open_or_create(ping, 1, 8, 1024);

  const pid_t child = fork();
  if (child == 0) {
    // Attach the ping reader BEFORE creating pong: the parent only starts
    // pinging once pong exists, so no ping can be sent before we listen.
    auto ping_r = open_retry(ping);
    auto pong_w = TableWriter::open_or_create(pong, 1, 8, 1024);
    while (true) {
      const auto v = receive(ping_r, spin);
      pong_w.write(SlotId{0}, bytes_of(v));
      if (v == kStop) _exit(0);
    }
  }

  auto pong_r = open_retry(pong);
  const std::uint64_t warmup = iters / 10;
  rg::LatencyRecorder one_way(iters);
  for (std::uint64_t i = 1; i <= iters + warmup; ++i) {
    const auto t0 = rg::now_ns();
    ping_w.write(SlotId{0}, bytes_of(i));
    while (receive(pong_r, spin) != i) {
    }
    const auto rtt = rg::now_ns() - t0;
    if (i > warmup) one_way.add(rtt / 2);
  }
  ping_w.write(SlotId{0}, bytes_of(kStop));
  int status = 0;
  waitpid(child, &status, 0);
  TableWriter::unlink(ping);
  TableWriter::unlink(pong);

  std::printf("  %-15s one-way %s\n", mode_name(spin),
              rg::LatencyRecorder::format(one_way.summarize(), 1000.0, "us").c_str());
}

void throughput() {
  constexpr std::size_t kSlots = 1 << 20;
  constexpr std::uint64_t kWrites = 10'000'000;
  const std::string name = "/rgbench.tp." + std::to_string(getpid());
  TableWriter::unlink(name);
  auto w = TableWriter::open_or_create(name, kSlots, sizeof(rg::pipeline::RouteRecord), 1 << 20);
  auto r = TableReader::open(name);
  rg::pipeline::RouteRecord rec{};
  rec.path_len = 6;

  auto t0 = std::chrono::steady_clock::now();
  for (std::uint64_t i = 0; i < kWrites; ++i) {
    rec.ingest_ns = i;
    w.write(SlotId{static_cast<std::uint32_t>((i * 2654435761ULL) % kSlots)},
            std::as_bytes(std::span<const rg::pipeline::RouteRecord, 1>(&rec, 1)));
  }
  double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  std::printf("  writes: %.2f M/s (%zu-byte records, random slots in a %zu-slot table, %.0f ns each)\n",
              static_cast<double>(kWrites) / s / 1e6, sizeof rec, kSlots, s * 1e9 / static_cast<double>(kWrites));

  std::uint64_t sink = 0;
  t0 = std::chrono::steady_clock::now();
  for (std::uint64_t i = 0; i < kWrites; ++i) {
    const auto res = r.read(SlotId{static_cast<std::uint32_t>((i * 2654435761ULL) % kSlots)},
                            std::as_writable_bytes(std::span<rg::pipeline::RouteRecord, 1>(&rec, 1)));
    sink += res.length + rec.ingest_ns;
  }
  s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  std::printf("  reads:  %.2f M/s (%.0f ns each) [chk %llu]\n", static_cast<double>(kWrites) / s / 1e6,
              s * 1e9 / static_cast<double>(kWrites), static_cast<unsigned long long>(sink % 10));
  TableWriter::unlink(name);
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t iters = 200'000;
  for (int i = 1; i + 1 < argc; ++i)
    if (std::string(argv[i]) == "--iters") iters = std::strtoull(argv[i + 1], nullptr, 10);

  std::printf("[1] cross-process notification latency (%llu round trips)\n", static_cast<unsigned long long>(iters));
  ping_pong(Mode::Futex, iters);
  ping_pong(Mode::BusyPoll, iters);
  ping_pong(Mode::SpinThenPark, iters);
  std::printf("[2] single-process throughput\n");
  throughput();
  return 0;
}
