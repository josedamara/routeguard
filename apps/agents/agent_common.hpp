#pragma once

// Small helpers shared by the agent executables.

#include <signal.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <span>
#include <string>
#include <string_view>
#include <thread>

#include "routeguard/state/state_store.hpp"

namespace rg::agent {

inline std::atomic<bool> g_stop{false};

inline void install_signal_handlers() {
  struct sigaction sa {};
  sa.sa_handler = [](int) { g_stop.store(true); };
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
}

// Agents can start in any order: wait for the upstream table to appear.
inline state::TableReader open_reader_with_retry(const std::string& name,
                                                 std::chrono::seconds timeout = std::chrono::seconds(60)) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (true) {
    try {
      return state::TableReader::open(name);
    } catch (const std::exception&) {
      if (g_stop.load() || std::chrono::steady_clock::now() > deadline) throw;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }
}

class Args {
 public:
  Args(int argc, char** argv) : argc_(argc), argv_(argv) {}

  bool has(std::string_view flag) const {
    for (int i = 1; i < argc_; ++i)
      if (flag == argv_[i]) return true;
    return false;
  }
  std::string get(std::string_view flag, std::string fallback = "") const {
    for (int i = 1; i + 1 < argc_; ++i)
      if (flag == argv_[i]) return argv_[i + 1];
    return fallback;
  }
  long long get_int(std::string_view flag, long long fallback) const {
    const auto v = get(flag);
    return v.empty() ? fallback : std::atoll(v.c_str());
  }

 private:
  int argc_;
  char** argv_;
};

template <typename T>
std::span<const std::byte> bytes_of(const T& v) {
  return std::as_bytes(std::span<const T, 1>(&v, 1));
}

template <typename T>
std::span<std::byte> writable_bytes_of(T& v) {
  return std::as_writable_bytes(std::span<T, 1>(&v, 1));
}

}  // namespace rg::agent
