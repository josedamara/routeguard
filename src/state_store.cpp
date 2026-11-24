#include "routeguard/state/state_store.hpp"

#include <fcntl.h>
#include <linux/futex.h>
#include <sched.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <bit>
#include <cerrno>
#include <climits>
#include <cstring>
#include <ctime>
#include <new>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace rg::state {
namespace detail {

constexpr std::uint64_t kMagic = 0x5247'5354'4F52'4531ULL;  // "RGSTORE1"
constexpr std::uint32_t kVersion = 1;

struct Header {
  std::atomic<std::uint64_t> magic;  // stored last, with release, once initialised
  std::uint32_t version;
  std::uint32_t reserved;
  std::uint64_t slot_count;
  std::uint64_t slot_size;    // payload capacity in bytes, multiple of 8
  std::uint64_t slot_stride;  // bytes per slot including its header, multiple of 64
  std::uint64_t ring_capacity;
  std::uint64_t ring_offset;
  std::uint64_t slots_offset;
  std::uint64_t total_size;
  alignas(64) std::atomic<std::uint64_t> head;  // change records ever published
  alignas(64) std::atomic<std::uint32_t> notify;  // futex word, bumped per publish
  std::atomic<std::uint32_t> waiters;             // readers blocked in futex_wait
};

struct SlotHeader {
  std::atomic<std::uint32_t> seq;  // seqlock: odd while a write is in progress
  std::atomic<std::uint32_t> length;
};

static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
static_assert(std::atomic<std::uint32_t>::is_always_lock_free);
static_assert(sizeof(std::atomic<std::uint32_t>) == sizeof(std::uint32_t));
static_assert(sizeof(SlotHeader) == 8);

Segment::Segment(Segment&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)),
      base_(std::exchange(other.base_, nullptr)),
      size_(std::exchange(other.size_, 0)) {}

Segment& Segment::operator=(Segment&& other) noexcept {
  if (this != &other) {
    reset();
    fd_ = std::exchange(other.fd_, -1);
    base_ = std::exchange(other.base_, nullptr);
    size_ = std::exchange(other.size_, 0);
  }
  return *this;
}

Segment::~Segment() { reset(); }

void Segment::reset() noexcept {
  if (base_ != nullptr) munmap(base_, size_);
  if (fd_ >= 0) close(fd_);  // also releases the writer's flock
  base_ = nullptr;
  fd_ = -1;
  size_ = 0;
}

}  // namespace detail

namespace {

using detail::Header;
using detail::SlotHeader;

struct Geometry {
  std::size_t slot_size, slot_stride, ring_capacity, ring_offset, slots_offset, total_size;
};

constexpr std::size_t round_up(std::size_t v, std::size_t a) { return (v + a - 1) / a * a; }

Geometry compute_geometry(std::size_t slot_count, std::size_t slot_size, std::size_t ring_capacity) {
  Geometry g{};
  g.slot_size = round_up(slot_size, 8);
  g.slot_stride = round_up(sizeof(SlotHeader) + g.slot_size, 64);  // no false sharing between slots
  g.ring_capacity = std::bit_ceil(std::max<std::size_t>(ring_capacity, 2));
  g.ring_offset = round_up(sizeof(Header), 64);
  g.slots_offset = round_up(g.ring_offset + g.ring_capacity * sizeof(std::uint64_t), 64);
  g.total_size = g.slots_offset + slot_count * g.slot_stride;
  return g;
}

std::string shm_path(const std::string& name) { return name.starts_with('/') ? name : "/" + name; }

[[noreturn]] void throw_errno(const std::string& what) {
  throw std::system_error(errno, std::generic_category(), what);
}

inline void cpu_relax() noexcept {
#if defined(__x86_64__) || defined(__i386__)
  __builtin_ia32_pause();
#endif
}

long futex(std::atomic<std::uint32_t>* word, int op, std::uint32_t val, const timespec* timeout) {
  // Not FUTEX_PRIVATE_FLAG: the word lives in memory shared between processes.
  return syscall(SYS_futex, reinterpret_cast<std::uint32_t*>(word), op, val, timeout, nullptr, 0);
}

std::atomic<std::uint64_t>* ring(std::byte* base, const Header* h) {
  return reinterpret_cast<std::atomic<std::uint64_t>*>(base + h->ring_offset);
}

SlotHeader* slot_header(std::byte* base, const Header* h, std::uint32_t slot) {
  if (slot >= h->slot_count) throw std::out_of_range("slot index out of range");
  return reinterpret_cast<SlotHeader*>(base + h->slots_offset + std::size_t{slot} * h->slot_stride);
}

std::atomic<std::uint64_t>* slot_words(SlotHeader* sh) {
  return reinterpret_cast<std::atomic<std::uint64_t>*>(reinterpret_cast<std::byte*>(sh) + sizeof(SlotHeader));
}

void initialise(std::byte* base, const Geometry& g, std::size_t slot_count) {
  auto* h = new (base) Header{};
  h->version = detail::kVersion;
  h->slot_count = slot_count;
  h->slot_size = g.slot_size;
  h->slot_stride = g.slot_stride;
  h->ring_capacity = g.ring_capacity;
  h->ring_offset = g.ring_offset;
  h->slots_offset = g.slots_offset;
  h->total_size = g.total_size;
  for (std::size_t i = 0; i < g.ring_capacity; ++i) {
    new (base + g.ring_offset + i * sizeof(std::uint64_t)) std::atomic<std::uint64_t>(~std::uint64_t{0});
  }
  const std::size_t words = g.slot_size / 8;
  for (std::size_t s = 0; s < slot_count; ++s) {
    std::byte* p = base + g.slots_offset + s * g.slot_stride;
    new (p) SlotHeader{};
    for (std::size_t w = 0; w < words; ++w) new (p + sizeof(SlotHeader) + w * 8) std::atomic<std::uint64_t>(0);
  }
  h->magic.store(detail::kMagic, std::memory_order_release);
}

}  // namespace

// ---------------------------------------------------------------- writer ---

TableWriter TableWriter::open_or_create(const std::string& name, std::size_t slot_count, std::size_t slot_size,
                                        std::size_t ring_capacity) {
  if (slot_count == 0 || slot_count > UINT32_MAX || slot_size == 0 || slot_size > UINT32_MAX) {
    throw std::invalid_argument("bad table geometry");
  }
  const auto path = shm_path(name);
  const Geometry g = compute_geometry(slot_count, slot_size, ring_capacity);

  const int fd = shm_open(path.c_str(), O_RDWR | O_CREAT, 0600);
  if (fd < 0) throw_errno("shm_open " + path);
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    const int err = errno;
    close(fd);
    throw std::system_error(err, std::generic_category(), "another writer owns " + path);
  }

  struct stat st {};
  if (fstat(fd, &st) != 0) {
    const int err = errno;
    close(fd);
    throw std::system_error(err, std::generic_category(), "fstat " + path);
  }
  const bool fresh = st.st_size == 0;
  if (fresh) {
    if (ftruncate(fd, static_cast<off_t>(g.total_size)) != 0) {
      const int err = errno;
      close(fd);
      throw std::system_error(err, std::generic_category(), "ftruncate " + path);
    }
  } else if (static_cast<std::size_t>(st.st_size) != g.total_size) {
    close(fd);
    throw std::runtime_error("table " + path + " exists with a different geometry");
  }

  void* base = mmap(nullptr, g.total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    const int err = errno;
    close(fd);
    throw std::system_error(err, std::generic_category(), "mmap " + path);
  }
  TableWriter writer(detail::Segment(fd, base, g.total_size));
  auto* bytes = static_cast<std::byte*>(base);
  auto* h = writer.seg_.header();

  if (fresh || h->magic.load(std::memory_order_acquire) != detail::kMagic) {
    initialise(bytes, g, slot_count);  // new table, or a previous writer died during init
    return writer;
  }
  if (h->slot_count != slot_count || h->slot_size != g.slot_size || h->ring_capacity != g.ring_capacity) {
    throw std::runtime_error("table " + path + " exists with a different geometry");
  }

  // Writer restart: repair slots a dead writer left mid-write.
  for (std::uint32_t s = 0; s < slot_count; ++s) {
    SlotHeader* sh = slot_header(bytes, h, s);
    const auto seq = sh->seq.load(std::memory_order_relaxed);
    if ((seq & 1U) != 0) {
      sh->length.store(0, std::memory_order_relaxed);
      sh->seq.store(seq + 1, std::memory_order_release);
      writer.publish(SlotId{s});
      ++writer.recovered_;
    }
  }
  return writer;
}

void TableWriter::unlink(const std::string& name) noexcept { shm_unlink(shm_path(name).c_str()); }

void TableWriter::write(SlotId slot, std::span<const std::byte> payload) {
  if (payload.empty() || payload.size() > slot_size()) throw std::invalid_argument("payload size out of range");
  store(slot, payload);
  publish(slot);
}

void TableWriter::erase(SlotId slot) {
  store(slot, {});
  publish(slot);
}

void TableWriter::store(SlotId slot, std::span<const std::byte> payload) {
  Header* h = seg_.header();
  SlotHeader* sh = slot_header(seg_.base(), h, slot.value);
  std::atomic<std::uint64_t>* words = slot_words(sh);

  const auto seq = sh->seq.load(std::memory_order_relaxed);
  sh->seq.store(seq + 1, std::memory_order_relaxed);  // odd: write in progress
  std::atomic_thread_fence(std::memory_order_release);

  sh->length.store(static_cast<std::uint32_t>(payload.size()), std::memory_order_relaxed);
  for (std::size_t off = 0, w = 0; off < payload.size(); off += 8, ++w) {
    std::uint64_t v = 0;
    std::memcpy(&v, payload.data() + off, std::min<std::size_t>(8, payload.size() - off));
    words[w].store(v, std::memory_order_relaxed);
  }

  sh->seq.store(seq + 2, std::memory_order_release);  // even: stable
}

void TableWriter::publish(SlotId slot) {
  Header* h = seg_.header();
  const auto head = h->head.load(std::memory_order_relaxed);
  // Tag each record with the low 32 bits of its sequence number so readers
  // can tell when the ring has lapped them.
  const std::uint64_t record = ((head & 0xFFFF'FFFFULL) << 32) | slot.value;
  ring(seg_.base(), h)[head & (h->ring_capacity - 1)].store(record, std::memory_order_release);
  h->head.store(head + 1, std::memory_order_release);

  h->notify.fetch_add(1, std::memory_order_seq_cst);
  if (h->waiters.load(std::memory_order_seq_cst) != 0) futex(&h->notify, FUTEX_WAKE, INT_MAX, nullptr);
}

std::size_t TableWriter::slot_count() const noexcept { return seg_.header()->slot_count; }
std::size_t TableWriter::slot_size() const noexcept { return seg_.header()->slot_size; }

void TableWriter::simulate_crash_mid_write(SlotId slot) {
  SlotHeader* sh = slot_header(seg_.base(), seg_.header(), slot.value);
  sh->seq.fetch_add(1, std::memory_order_release);  // odd, never made even again
  slot_words(sh)[0].store(0xDEAD'BEEF'DEAD'BEEFULL, std::memory_order_relaxed);
}

// ---------------------------------------------------------------- reader ---

TableReader::TableReader(detail::Segment seg) : seg_(std::move(seg)) {
  cursor_ = seg_.header()->head.load(std::memory_order_acquire);
}

TableReader TableReader::open(const std::string& name) {
  const auto path = shm_path(name);
  // Read-write: readers update the futex waiter count.
  const int fd = shm_open(path.c_str(), O_RDWR, 0);
  if (fd < 0) throw_errno("shm_open " + path);
  struct stat st {};
  if (fstat(fd, &st) != 0 || static_cast<std::size_t>(st.st_size) < sizeof(Header)) {
    close(fd);
    throw std::runtime_error("table " + path + " is not initialised yet");
  }
  const auto size = static_cast<std::size_t>(st.st_size);
  void* base = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    const int err = errno;
    close(fd);
    throw std::system_error(err, std::generic_category(), "mmap " + path);
  }
  detail::Segment seg(fd, base, size);
  const Header* h = seg.header();
  if (h->magic.load(std::memory_order_acquire) != detail::kMagic || h->total_size != size) {
    throw std::runtime_error("table " + path + " is not initialised yet");
  }
  return TableReader(std::move(seg));
}

ReadResult TableReader::read(SlotId slot, std::span<std::byte> out) const {
  constexpr int kMaxSpins = 1 << 20;
  const Header* h = seg_.header();
  SlotHeader* sh = slot_header(seg_.base(), h, slot.value);
  const std::atomic<std::uint64_t>* words = slot_words(sh);

  for (int spin = 0; spin < kMaxSpins; ++spin) {
    const auto s1 = sh->seq.load(std::memory_order_acquire);
    if ((s1 & 1U) != 0) {
      cpu_relax();
      if ((spin & 1023) == 1023) sched_yield();  // writer may have been preempted
      continue;
    }
    const std::size_t length = sh->length.load(std::memory_order_relaxed);
    const std::size_t n = std::min({length, out.size(), static_cast<std::size_t>(h->slot_size)});
    for (std::size_t off = 0, w = 0; off < n; off += 8, ++w) {
      const std::uint64_t v = words[w].load(std::memory_order_relaxed);
      std::memcpy(out.data() + off, &v, std::min<std::size_t>(8, n - off));
    }
    std::atomic_thread_fence(std::memory_order_acquire);
    if (sh->seq.load(std::memory_order_relaxed) == s1) {
      if (length == 0) return {ReadResult::Status::Empty, 0};
      return {ReadResult::Status::Ok, length};
    }
  }
  return {ReadResult::Status::Busy, 0};
}

TableReader::Changes TableReader::drain_changes(std::span<SlotId> out) {
  const Header* h = seg_.header();
  const auto* records = ring(seg_.base(), h);
  const auto head = h->head.load(std::memory_order_acquire);
  if (head - cursor_ > h->ring_capacity) {
    cursor_ = head;
    return {0, true};
  }
  Changes result;
  while (cursor_ < head && result.count < out.size()) {
    const auto record = records[cursor_ & (h->ring_capacity - 1)].load(std::memory_order_acquire);
    if ((record >> 32) != (cursor_ & 0xFFFF'FFFFULL)) {  // overwritten while we read
      cursor_ = h->head.load(std::memory_order_acquire);
      result.overflowed = true;
      return result;
    }
    out[result.count++] = SlotId{static_cast<std::uint32_t>(record)};
    ++cursor_;
  }
  return result;
}

bool TableReader::has_changes() const noexcept {
  return seg_.header()->head.load(std::memory_order_acquire) != cursor_;
}

bool TableReader::wait_for_changes(std::chrono::nanoseconds timeout) {
  if (has_changes()) return true;
  Header* h = seg_.header();
  const auto deadline = std::chrono::steady_clock::now() + timeout;

  h->waiters.fetch_add(1, std::memory_order_seq_cst);
  bool ready = false;
  while (true) {
    const auto seen = h->notify.load(std::memory_order_seq_cst);
    if (has_changes()) {
      ready = true;
      break;
    }
    const auto remaining = deadline - std::chrono::steady_clock::now();
    if (remaining <= std::chrono::nanoseconds::zero()) break;
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(remaining).count();
    const timespec ts{static_cast<time_t>(ns / 1'000'000'000), static_cast<long>(ns % 1'000'000'000)};
    // Returns immediately if notify != seen, i.e. a write raced with us.
    futex(&h->notify, FUTEX_WAIT, seen, &ts);
  }
  h->waiters.fetch_sub(1, std::memory_order_seq_cst);
  return ready;
}

std::size_t TableReader::slot_count() const noexcept { return seg_.header()->slot_count; }
std::size_t TableReader::slot_size() const noexcept { return seg_.header()->slot_size; }

}  // namespace rg::state
