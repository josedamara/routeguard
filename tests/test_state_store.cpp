#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#include "routeguard/state/state_store.hpp"
#include "test_framework.hpp"

using rg::state::ReadResult;
using rg::state::SlotId;
using rg::state::TableReader;
using rg::state::TableWriter;

namespace {

std::string unique_name(const char* tag) { return "/rgtest." + std::string(tag) + "." + std::to_string(getpid()); }

struct Unlink {
  std::string name;
  ~Unlink() { TableWriter::unlink(name); }
};

template <typename T>
std::span<const std::byte> bytes_of(const T& v) {
  return std::as_bytes(std::span<const T, 1>(&v, 1));
}

int wait_child(pid_t pid) {
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

}  // namespace

RG_TEST(store_write_read_erase) {
  const auto name = unique_name("basic");
  Unlink cleanup{name};
  auto writer = TableWriter::open_or_create(name, 16, 24, 8);
  auto reader = TableReader::open(name);
  std::array<std::byte, 24> buf{};

  RG_CHECK(reader.read(SlotId{3}, buf).status == ReadResult::Status::Empty);

  const char msg[] = "hello state";
  writer.write(SlotId{3}, std::as_bytes(std::span(msg)));
  const auto res = reader.read(SlotId{3}, buf);
  RG_CHECK(res.status == ReadResult::Status::Ok);
  RG_CHECK(res.length == sizeof msg);
  RG_CHECK(std::memcmp(buf.data(), msg, sizeof msg) == 0);

  std::array<SlotId, 8> changes{};
  const auto c = reader.drain_changes(changes);
  RG_CHECK(c.count == 1 && changes[0].value == 3 && !c.overflowed);
  RG_CHECK(!reader.has_changes());

  writer.erase(SlotId{3});
  RG_CHECK(reader.read(SlotId{3}, buf).status == ReadResult::Status::Empty);
  RG_CHECK(reader.drain_changes(changes).count == 1);
}

RG_TEST(store_ring_overflow_requests_resync) {
  const auto name = unique_name("overflow");
  Unlink cleanup{name};
  auto writer = TableWriter::open_or_create(name, 4, 8, 8);
  auto reader = TableReader::open(name);
  for (std::uint64_t i = 0; i < 20; ++i) writer.write(SlotId{static_cast<std::uint32_t>(i % 4)}, bytes_of(i));

  std::array<SlotId, 32> changes{};
  const auto c = reader.drain_changes(changes);
  RG_CHECK(c.overflowed);
  RG_CHECK(reader.drain_changes(changes).count == 0);  // cursor moved to head

  writer.write(SlotId{1}, bytes_of(std::uint64_t{7}));
  const auto c2 = reader.drain_changes(changes);
  RG_CHECK(c2.count == 1 && !c2.overflowed && changes[0].value == 1);
}

RG_TEST(store_single_writer_and_geometry_checks) {
  const auto name = unique_name("single");
  Unlink cleanup{name};
  {
    auto writer = TableWriter::open_or_create(name, 8, 16, 8);
    bool rejected = false;
    try {
      auto second = TableWriter::open_or_create(name, 8, 16, 8);
    } catch (const std::system_error&) {
      rejected = true;
    }
    RG_CHECK(rejected);
  }
  bool mismatch = false;
  try {
    auto other = TableWriter::open_or_create(name, 9, 16, 8);
  } catch (const std::runtime_error&) {
    mismatch = true;
  }
  RG_CHECK(mismatch);
  auto again = TableWriter::open_or_create(name, 8, 16, 8);  // same geometry: re-attach
  RG_CHECK(again.recovered_slots() == 0);
}

RG_TEST(store_cross_process_reads_are_never_torn) {
  constexpr std::uint64_t kIters = 200'000;
  constexpr std::size_t kWords = 32;  // 256-byte payload
  const auto name = unique_name("torn");
  Unlink cleanup{name};
  { auto init = TableWriter::open_or_create(name, 2, kWords * 8, 64); }  // create, then release

  const pid_t pid = fork();
  if (pid == 0) {
    try {
      auto writer = TableWriter::open_or_create(name, 2, kWords * 8, 64);
      std::array<std::uint64_t, kWords> payload{};
      for (std::uint64_t k = 1; k <= kIters; ++k) {
        payload.fill(k);
        writer.write(SlotId{0}, std::as_bytes(std::span(payload)));
      }
      _exit(0);
    } catch (...) {
      _exit(1);
    }
  }

  auto reader = TableReader::open(name);
  std::array<std::uint64_t, kWords> seen{};
  std::uint64_t last = 0, reads = 0, torn = 0, backwards = 0;
  int status = 0;
  while (waitpid(pid, &status, WNOHANG) == 0) {
    const auto r = reader.read(SlotId{0}, std::as_writable_bytes(std::span(seen)));
    if (r.status != ReadResult::Status::Ok) continue;
    ++reads;
    for (auto w : seen) torn += (w != seen[0]) ? 1 : 0;
    if (seen[0] < last) ++backwards;
    last = seen[0];
  }
  RG_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  RG_CHECK(reads > 0);
  RG_CHECK(torn == 0);
  RG_CHECK(backwards == 0);
  reader.read(SlotId{0}, std::as_writable_bytes(std::span(seen)));
  RG_CHECK(seen[0] == kIters && seen[kWords - 1] == kIters);
}

RG_TEST(store_futex_wait_wakes_on_write) {
  const auto name = unique_name("wake");
  Unlink cleanup{name};
  { auto init = TableWriter::open_or_create(name, 2, 8, 8); }
  auto reader = TableReader::open(name);

  RG_CHECK(!reader.wait_for_changes(std::chrono::milliseconds(20)));  // times out, nothing written

  const pid_t pid = fork();
  if (pid == 0) {
    try {
      auto writer = TableWriter::open_or_create(name, 2, 8, 8);
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      writer.write(SlotId{1}, bytes_of(std::uint64_t{42}));
      _exit(0);
    } catch (...) {
      _exit(1);
    }
  }
  const auto start = std::chrono::steady_clock::now();
  const bool woke = reader.wait_for_changes(std::chrono::seconds(5));
  const auto elapsed = std::chrono::steady_clock::now() - start;
  RG_CHECK(woke);
  RG_CHECK(elapsed < std::chrono::seconds(2));
  RG_CHECK(wait_child(pid) == 0);
}

RG_TEST(store_recovers_from_writer_killed_mid_write) {
  const auto name = unique_name("crash");
  Unlink cleanup{name};
  {
    auto writer = TableWriter::open_or_create(name, 4, 8, 8);
    writer.write(SlotId{2}, bytes_of(std::uint64_t{1}));
  }
  const pid_t pid = fork();
  if (pid == 0) {
    try {
      auto writer = TableWriter::open_or_create(name, 4, 8, 8);
      writer.simulate_crash_mid_write(SlotId{2});
      _exit(0);  // no destructors run, like a kill -9; the kernel drops the flock
    } catch (...) {
      _exit(1);
    }
  }
  RG_CHECK(wait_child(pid) == 0);

  auto reader = TableReader::open(name);
  std::array<std::byte, 8> buf{};
  RG_CHECK(reader.read(SlotId{2}, buf).status == ReadResult::Status::Busy);

  auto restarted = TableWriter::open_or_create(name, 4, 8, 8);
  RG_CHECK(restarted.recovered_slots() == 1);
  RG_CHECK(reader.read(SlotId{2}, buf).status == ReadResult::Status::Empty);
  std::array<SlotId, 4> changes{};
  const auto c = reader.drain_changes(changes);
  RG_CHECK(c.count == 1 && changes[0].value == 2);
}
