#pragma once

// =============================================================================
// Stage 2: shared-memory state store. INTERFACE ONLY, NOT IMPLEMENTED YET.
// =============================================================================
//
// Goal: let independent agent processes (feed ingest, ROV/ASPA validator,
// FIB, alerting) share state without going through a central server on the
// hot path, and let any agent crash and restart without losing state. This is
// the same idea as EOS agents sharing state through Sysdb.
//
// Suggested design. Implement it yourself and be ready to defend each choice
// in an interview:
//   * One POSIX shared-memory segment per table (shm_open + ftruncate + mmap).
//   * Fixed-size slots, each guarded by a seqlock: one writer, lock-free
//     readers that retry if the sequence number changed under them.
//   * A ring buffer of change records (slot id + sequence number) so readers
//     can consume deltas instead of rescanning; wake readers with an eventfd
//     (pollable with epoll) or a futex instead of busy-polling.
//   * A reader that falls a full ring behind resyncs by scanning all slots.
//   * A writer that crashes mid-write leaves an odd seqlock counter. Decide
//     how a restarted writer detects and repairs that.
//   * Test with one writer and N readers under ThreadSanitizer, and with a
//     writer you kill -9 in a loop.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace rg::state {

struct SlotId {
  std::uint32_t value = 0;
};

class TableWriter {
 public:
  static TableWriter create(const std::string& name, std::size_t slot_count, std::size_t slot_size);
  void write(SlotId slot, std::span<const std::byte> data);
  void erase(SlotId slot);
};

class TableReader {
 public:
  static TableReader open(const std::string& name);
  // Copies a consistent snapshot of the slot into `out`; false if empty.
  bool read(SlotId slot, std::span<std::byte> out) const;
  // Fills `out` with slots changed since the last call; returns how many.
  std::size_t drain_changes(std::span<SlotId> out);
  // A file descriptor that becomes readable when there are new changes.
  int notify_fd() const;
};

}  // namespace rg::state
