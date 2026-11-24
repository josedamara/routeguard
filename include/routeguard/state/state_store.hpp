#pragma once

// Shared-memory state store: lets independent agent processes share tables
// of fixed-size records without a broker on the hot path, and lets any agent
// crash and restart without losing state. Same idea as EOS agents sharing
// state through Sysdb.
//
// Design
//   * One POSIX shared-memory segment per table (shm_open + mmap). Layout:
//       [Header][change ring: ring_capacity x u64][slot 0][slot 1]...
//   * Single writer per table, enforced with flock(): the kernel drops the
//     lock when the writer dies, so a restarted writer can take over.
//   * Each slot is guarded by a seqlock. The writer bumps the sequence to odd,
//     stores the payload, bumps it back to even. Readers never block the
//     writer; they retry if the sequence moved under them. Payload words are
//     accessed through relaxed atomics, so there is no data race (TSan clean).
//   * Every write appends (sequence, slot) to a ring of change records, so
//     readers consume deltas instead of rescanning. A reader that falls more
//     than ring_capacity behind is told to resync with a full scan.
//   * Readers sleep on a futex in shared memory, so an idle reader costs no
//     CPU and wakes within microseconds of a write.
//   * A writer killed mid-write leaves an odd sequence. When a writer
//     re-attaches, it clears those torn slots and publishes them as changed.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace rg::state {

struct SlotId {
  std::uint32_t value = 0;
};

namespace detail {
struct Header;

// Owns one mmap'd segment. Move-only.
class Segment {
 public:
  Segment() = default;
  Segment(int fd, void* base, std::size_t size) : fd_(fd), base_(base), size_(size) {}
  Segment(Segment&& other) noexcept;
  Segment& operator=(Segment&& other) noexcept;
  Segment(const Segment&) = delete;
  Segment& operator=(const Segment&) = delete;
  ~Segment();

  Header* header() const noexcept { return static_cast<Header*>(base_); }
  std::byte* base() const noexcept { return static_cast<std::byte*>(base_); }
  int fd() const noexcept { return fd_; }

 private:
  void reset() noexcept;
  int fd_ = -1;
  void* base_ = nullptr;
  std::size_t size_ = 0;
};
}  // namespace detail

struct ReadResult {
  enum class Status : std::uint8_t { Ok, Empty, Busy };
  Status status = Status::Empty;
  std::size_t length = 0;  // payload bytes when status == Ok
};

class TableWriter {
 public:
  // Creates the table, or re-attaches to an existing one with the same
  // geometry (writer restart). Throws std::system_error if another live
  // process is already the writer, std::runtime_error on geometry mismatch.
  // ring_capacity is rounded up to a power of two.
  static TableWriter open_or_create(const std::string& name, std::size_t slot_count, std::size_t slot_size,
                                    std::size_t ring_capacity = 1U << 16);

  // Removes the table's name. Mapped segments stay valid until unmapped.
  static void unlink(const std::string& name) noexcept;

  // Payload must be 1..slot_size bytes.
  void write(SlotId slot, std::span<const std::byte> payload);
  // Clears the slot; readers then see ReadResult::Status::Empty.
  void erase(SlotId slot);

  std::size_t slot_count() const noexcept;
  std::size_t slot_size() const noexcept;
  // Torn slots repaired when this writer attached to an existing table.
  std::size_t recovered_slots() const noexcept { return recovered_; }

  // Test hook: leaves `slot` exactly as a writer killed mid-write would.
  void simulate_crash_mid_write(SlotId slot);

 private:
  explicit TableWriter(detail::Segment seg) : seg_(std::move(seg)) {}
  void store(SlotId slot, std::span<const std::byte> payload);
  void publish(SlotId slot);

  detail::Segment seg_;
  std::size_t recovered_ = 0;
};

class TableReader {
 public:
  // Throws std::system_error if the table does not exist yet and
  // std::runtime_error if it exists but is not initialised yet.
  static TableReader open(const std::string& name);

  // Copies a consistent snapshot of the slot into `out` (which should be at
  // least slot_size() bytes; longer payloads are truncated). Busy means the
  // slot stayed mid-write for the whole spin budget, e.g. its writer died.
  ReadResult read(SlotId slot, std::span<std::byte> out) const;

  struct Changes {
    std::size_t count = 0;    // entries written to `out`
    bool overflowed = false;  // fell behind the ring: rescan every slot
  };
  // Fills `out` with slots changed since the previous call. A slot may
  // appear more than once; read() always returns its latest contents.
  Changes drain_changes(std::span<SlotId> out);

  // Blocks until there are undrained changes or the timeout expires.
  bool wait_for_changes(std::chrono::nanoseconds timeout);

  bool has_changes() const noexcept;
  std::size_t slot_count() const noexcept;
  std::size_t slot_size() const noexcept;

 private:
  explicit TableReader(detail::Segment seg);
  detail::Segment seg_;
  std::uint64_t cursor_ = 0;
};

}  // namespace rg::state
