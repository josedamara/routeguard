// libFuzzer target for the MRT decoder (clang only):
//   cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ -DROUTEGUARD_FUZZ=ON
//   cmake --build build-fuzz --target fuzz_mrt
//   ./build-fuzz/fuzz_mrt -max_total_time=60
//
// The decoder parses untrusted binary input from the network, so it must
// never read out of bounds or hit undefined behaviour on any byte sequence.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "routeguard/mrt.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  std::vector<rg::BgpUpdate> out;
  rg::MrtStats stats;
  const auto used = rg::decode_mrt_buffer(std::span(data, size), out, &stats);
  if (used > size) __builtin_trap();
  for (const auto& u : out) {
    if (u.prefix.length() > u.prefix.max_length()) __builtin_trap();
  }
  return 0;
}
