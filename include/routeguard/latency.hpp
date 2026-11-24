#pragma once

#include <time.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace rg {

// CLOCK_MONOTONIC is system-wide, so timestamps taken in different processes
// can be subtracted directly.
inline std::uint64_t now_ns() noexcept {
  timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL + static_cast<std::uint64_t>(ts.tv_nsec);
}

// Collects raw latency samples and reports exact percentiles.
class LatencyRecorder {
 public:
  explicit LatencyRecorder(std::size_t reserve = 1U << 20) { samples_.reserve(reserve); }

  void add(std::uint64_t ns) { samples_.push_back(ns); }
  std::size_t count() const noexcept { return samples_.size(); }

  struct Summary {
    std::size_t count = 0;
    double mean_ns = 0;
    std::uint64_t p50 = 0, p90 = 0, p99 = 0, p999 = 0, max = 0;
  };

  Summary summarize() const {
    Summary s;
    if (samples_.empty()) return s;
    std::vector<std::uint64_t> v = samples_;
    std::sort(v.begin(), v.end());
    auto pct = [&](double p) { return v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))]; };
    double sum = 0;
    for (auto x : v) sum += static_cast<double>(x);
    s.count = v.size();
    s.mean_ns = sum / static_cast<double>(v.size());
    s.p50 = pct(0.50);
    s.p90 = pct(0.90);
    s.p99 = pct(0.99);
    s.p999 = pct(0.999);
    s.max = v.back();
    return s;
  }

  // "n=... mean=... p50=... p90=... p99=... p99.9=... max=..." in microseconds
  // (unit_ns = 1000) or nanoseconds (unit_ns = 1).
  static std::string format(const Summary& s, double unit_ns = 1000.0, const char* unit = "us") {
    char buf[256];
    std::snprintf(buf, sizeof buf, "n=%zu mean=%.2f%s p50=%.2f%s p90=%.2f%s p99=%.2f%s p99.9=%.2f%s max=%.2f%s",
                  s.count, s.mean_ns / unit_ns, unit, static_cast<double>(s.p50) / unit_ns, unit,
                  static_cast<double>(s.p90) / unit_ns, unit, static_cast<double>(s.p99) / unit_ns, unit,
                  static_cast<double>(s.p999) / unit_ns, unit, static_cast<double>(s.max) / unit_ns, unit);
    return buf;
  }

 private:
  std::vector<std::uint64_t> samples_;
};

}  // namespace rg
