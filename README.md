# RouteGuard

[![ci](https://github.com/josedamara/routeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/josedamara/routeguard/actions/workflows/ci.yml)

A BGP route-security monitor in C++20 for Linux. It reads raw BGP data from RIPE RIS,
checks each route against the global RPKI with **origin validation (RFC 6811)** and
**ASPA path validation**, and flags hijacks and route leaks. It runs as **three separate
processes** that share state through a lock-free **shared-memory store** I built from scratch,
the same architecture a state-based network OS uses.

On one hour of real Internet routing data (6.5 M updates, 1.04 M VRPs) the three-process
pipeline sustains **1.43 M updates/s with zero drops**. At 100 K updates/s, end-to-end latency
from ingest to alert is **0.78 µs at p50 and 68 µs at p99**. Full numbers:
[results/BENCHMARKS.md](results/BENCHMARKS.md).

## Why

- RPKI origin validation now covers about two-thirds of announced prefixes, but it only checks
  **who originates** a route, not **the path it took**. Route leaks and forged-origin hijacks pass it.
- ASPA (path validation) closes that gap, but only about 2.5% of ASes publish ASPA records so far.
- Global route leaks and hijacks still happen every quarter.

## Architecture

```
 RIPE RIS MRT ──▶ routeguard-ingest ──▶ rg.routes ──▶ routeguard-validator ──▶ rg.verdicts ──▶ routeguard-alert
 (raw binary)     one slot per           (shm table)   ROV + ASPA on every       (shm table)     prints failing
                  (peer, prefix)                       changed slot                              routes + latency
```

**Shared-memory state store** (`src/state_store.cpp`)
- One POSIX shared-memory segment per table. A single writer is enforced with `flock`, which the
  kernel releases if the writer dies.
- Each slot has a **seqlock**. Readers never block the writer and retry if a write raced them.
  Payloads are copied through relaxed atomics, so there are no data races.
- A **change ring** lets readers consume deltas instead of rescanning. A reader that falls behind is
  told to resync with one full scan.
- **Spin-then-park wakeups.** Readers spin for up to 50 µs and then sleep on a cross-process **futex**.
  They get busy-poll latency (0.20 µs) and use zero CPU when idle.
- **Crash recovery.** A writer killed mid-write leaves an odd sequence number. The next writer detects
  it and repairs the slot.

**Agents** (`apps/agents/`)
- Any agent can be killed and restarted.
- Ingest rebuilds its `(peer, prefix) → slot` index by scanning its table.
- The validator rescans on start, so it converges on the current state.

**Validation**
- `PrefixTrie`: a binary trie stored in one vector and linked by index, so it is also safe to place
  in shared memory.
- `PatriciaTrie`: a path-compressed alternative. I benchmarked both and kept the faster one
  ([results](results/BENCHMARKS.md#4-binary-trie-vs-patricia-trie-all-104-m-vrp-prefixes)).
- RFC 6811 origin validation.
- ASPA upstream and downstream verification (draft-ietf-sidrops-aspa-verification).

**MRT decoder** (`src/mrt.cpp`)
- An RFC 6396 BGP4MP parser with bounds-checked big-endian reads.
- Handles IPv4 NLRI, MP_REACH / MP_UNREACH for IPv6, and 2- and 4-byte AS paths with RFC 6793
  AS4_PATH merging.
- Fuzzed with libFuzzer in CI.

### Design trade-off: state, not events

Like a state-based OS, the store keeps the **latest state** of each route rather than a log of every
message. If a route is announced and withdrawn faster than the validator reacts (sub-microsecond at
normal load), the two updates coalesce. Readers always converge to the current state, and memory is
bounded by the number of routes rather than the message rate. Catching every transient event would
need an event log next to the state table.

## Build, test, run (Linux / WSL)

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DROUTEGUARD_SANITIZE=ON
cmake --build build
ctest --test-dir build --output-on-failure      # unit tests + 3-process pipeline test
```

Without CMake: `scripts/dev_build.sh debug` (tests with ASan/UBSan), `tsan`, or `release`.

Single process:

```bash
./build/routeguard --roas data/sample_roas.csv --updates data/sample_updates.txt --all
```

Real data, three processes:

```bash
python3 scripts/fetch_vrps.py                      # global VRPs + ASPAs -> data/*.csv
scripts/fetch_ris_updates.sh 2026-11-23 12 rrc00    # one hour of raw BGP updates
gunzip -c data/ris/updates.*.gz > rrc00-1h.mrt
scripts/run_pipeline.sh build data/vrps.csv data/aspas.csv rrc00-1h.mrt 100000
```

Docker: `docker build -t routeguard . && docker run --rm routeguard`

## Testing

- **43 unit tests** (dependency-free harness):
  - RFC 6811 edge cases and ASPA leak / valley-free scenarios.
  - MRT wire-format records encoded by hand.
  - Both tries checked against a brute-force reference on thousands of random prefixes.
  - Cross-process store tests: 200 K writes with zero torn reads, futex wakeup, ring overflow,
    single-writer enforcement, and crash recovery.
- **Pipeline integration test.** Starts three real processes and checks the alerts, the ingest index
  rebuild after a restart, and that a late-starting validator converges.
- **CI** (GitHub Actions): gcc and clang, each with and without ASan + UBSan, warnings as errors.
  It also runs 2 minutes of libFuzzer (about 17 M inputs) and a Docker build.

## Layout

```
include/routeguard/   prefix, prefix_trie, patricia_trie, rpki, aspa, mrt, bgp_update,
                      pipeline (shared records), latency, state/state_store
src/                  implementation
apps/                 routeguard CLI; agents/ (ingest, validator, alert)
bench/                bench_lookup (validation path), bench_store (shared-memory store)
fuzz/                 libFuzzer target for the MRT decoder
tests/                unit tests, MRT record builder, pipeline integration test
scripts/              data fetchers, dev build, pipeline runner
results/              BENCHMARKS.md
```

## Resume bullets

- Built **RouteGuard**, a C++20 BGP security monitor that validates live Internet routes against the
  global RPKI (RFC 6811 origin validation and ASPA path validation). It found 2 K RPKI-invalid and
  14 K ASPA-invalid routes in one hour of RIPE RIS data.
- Designed a **lock-free shared-memory state store** (seqlocks, change ring, cross-process futex,
  crash recovery) connecting three agent processes. It sustains **1.43 M updates/s with zero drops**,
  with **0.78 µs p50 / 68 µs p99** end-to-end latency at 100 K updates/s.
- Cut cross-process wakeup latency from **17.6 µs to 0.20 µs** with spin-then-park futex waits. That
  removed all reader resyncs at full load and lowered p99 at 250 K updates/s from **90 ms to 153 µs**.
- Wrote a bounds-checked **MRT/BGP binary parser** (RFC 6396, RFC 4760, RFC 6793) decoding
  **4.9 M prefix updates/s**. Fuzzed it with libFuzzer (about 17 M inputs per CI run) under ASan and
  UBSan.
- Benchmarked binary vs Patricia tries on 1.04 M prefixes (130 vs 210 ns lookups; 108 vs 90 MiB) and
  chose the index from the data. Word-level prefix comparison made origin validation **2.2× faster**
  (370 → 167 ns per route).
