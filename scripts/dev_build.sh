#!/usr/bin/env bash
# Build and test without CMake (plain g++), mirroring CMakeLists.txt.
# Useful on machines without cmake. Usage:
#   scripts/dev_build.sh            # debug + ASan/UBSan, run tests
#   scripts/dev_build.sh release    # -O2 -march=native, for benchmarks
#   scripts/dev_build.sh tsan       # ThreadSanitizer, run tests
set -euo pipefail
cd "$(dirname "$0")/.."

mode=${1:-debug}
out=${OUT:-/tmp/rg-build-$mode}
mkdir -p "$out"

common="-std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror -Iinclude -Isrc"
case "$mode" in
  debug)   flags="$common -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" ;;
  tsan)    flags="$common -g -O1 -fsanitize=thread" ;;
  release) flags="$common -O2 -march=native -DNDEBUG -g" ;;
  *) echo "unknown mode $mode" >&2; exit 2 ;;
esac

core=$(ls src/*.cpp)
build() {  # build <output> <sources...>
  local target=$1; shift
  g++ $flags $core "$@" -o "$out/$target" &
}

build routeguard apps/routeguard.cpp
build routeguard_tests tests/*.cpp
for app in apps/agents/*.cpp; do
  [[ -e "$app" ]] || continue
  build "routeguard-$(basename "$app" .cpp)" "$app"
done
for bench in bench/*.cpp; do
  [[ -e "$bench" ]] || continue
  build "$(basename "$bench" .cpp)" "$bench"
done
wait

echo "built into $out"
if [[ "$mode" != release ]]; then
  "$out/routeguard_tests"
  "$out/routeguard" --roas data/sample_roas.csv --updates data/sample_updates.txt > /dev/null
fi
