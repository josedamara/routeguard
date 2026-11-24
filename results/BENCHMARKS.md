# Benchmarks

All numbers measured on 2026-11-24 with real Internet data:

- **BGP updates:** one hour of raw MRT from RIPE RIS `rrc00` (2026-11-23 12:00–12:55 UTC),
  12 files, 340 MiB uncompressed, 2.18 M MRT records → **6.49 M prefix updates**
  (5.73 M announcements, 0.76 M withdrawals) from 833 K distinct (peer, prefix) routes.
- **RPKI:** the full global set from `console.rpki-client.org`, **1,039,214 VRPs** and **4,304 ASPAs**.

Machine: Intel Core i7-12700H laptop (20 threads), Windows 11 + WSL2 (Linux 6.18), g++ 11.4,
`-O2 -march=native`. WSL2 adds scheduler noise, so p99.9 and max are pessimistic; p50 / p99 are the
representative numbers.

Reproduce:

```bash
scripts/fetch_ris_updates.sh 2026-11-23 12 rrc00 && python3 scripts/fetch_vrps.py
gunzip -c data/ris/updates.*.gz > rrc00-1h.mrt
scripts/dev_build.sh release            # or the CMake build
BIN=~/.cache/routeguard/build-release
$BIN/bench_lookup --vrps data/vrps.csv --aspas data/aspas.csv --mrt rrc00-1h.mrt
$BIN/bench_store --iters 200000
scripts/run_pipeline.sh $BIN data/vrps.csv data/aspas.csv rrc00-1h.mrt 100000   # rate, 0 = max
```

## 1. Three-process pipeline, end to end (ingest → validator → alert)

Each stage is a separate process; they share state only through the shared-memory store.
Latency = `CLOCK_MONOTONIC` at alert minus the timestamp ingest wrote into the record.

| Replay rate | Routes validated | Dropped | Ring resyncs | p50 | p90 | p99 |
|---|---|---|---|---|---|---|
| 100 K updates/s (55× real time) | 5.73 M | 0 | 0 | **0.78 µs** | 2.2 µs | **68 µs** |
| 250 K updates/s | 5.73 M | 0 | 0 | 0.81 µs | 3.3 µs | 153 µs |
| 500 K updates/s | 5.73 M | 0 | 0 | 0.77 µs | 3.0 µs | 151 µs |
| max: **1.43 M updates/s** | 5.74 M | 0 | **0** | 2.1 µs | 59 µs | 6.0 ms |

### Effect of spin-then-park wakeups

Readers originally slept on the futex as soon as they ran out of work, so almost every write paid a
`FUTEX_WAKE` syscall. Spinning for up to 50 µs before parking removed that:

| Rate | p50 before → after | p99 before → after | resyncs before → after |
|---|---|---|---|
| 100 K/s | 16.7 µs → 0.78 µs | 468 µs → 68 µs | 0 → 0 |
| 250 K/s | 46 µs → 0.81 µs | 90 ms → 153 µs | 0 → 0 |
| max | 653 ms → 2.1 µs | 4.6 s → 6.0 ms | 4 → 0 |

## 2. Shared-memory store (`bench_store`)

Cross-process ping-pong, 200 K round trips, one-way latency = RTT / 2:

| Reader strategy | p50 | p99 | p99.9 | CPU when idle |
|---|---|---|---|---|
| futex only | 17.6 µs | 37.9 µs | 69 µs | none |
| busy-poll | 0.22 µs | 0.25 µs | 0.34 µs | 100% of a core |
| **spin-then-park (default)** | **0.20 µs** | **0.24 µs** | 0.85 µs | none after 50 µs |

Single process, 248-byte route records, random slots in a 1 M-slot (256 MiB) table:
**3.6 M writes/s** (278 ns) and **3.3 M reads/s** (300 ns); dominated by cache misses.

Correctness under concurrency (unit tests): 200 K writes from one process against a reader process
with zero torn reads; a writer killed mid-write is detected and repaired on restart.

## 3. Validation path, single thread (`bench_lookup`)

| Stage | Throughput | Per item |
|---|---|---|
| MRT decode (bounds-checked) | **255 MiB/s, 4.86 M prefix updates/s** | 0 malformed of 2.18 M records |
| RFC 6811 ROV (1.04 M VRPs) | **5.98 M routes/s** | avg 167 ns, p50 125 ns, p99 1.6 µs |
| ASPA path verification | **9.86 M paths/s** | avg 101 ns, p50 98 ns, p99 0.65 µs |
| decode + ROV + ASPA | **1.48 M updates/s** | 4.4 s for the whole hour |

Per-call percentiles include ~21 ns of timer overhead.

Findings in that hour: 2,013 RPKI-invalid announcements, 14,480 ASPA-invalid paths (routes received
via collector peers, checked with the permissive downstream procedure).

## 4. Binary trie vs Patricia trie (all 1.04 M VRP prefixes)

| | Build | Nodes | Memory | Longest-prefix match |
|---|---|---|---|---|
| Binary trie | 259 ms | 2.39 M | 108 MiB | **130 ns** (7.7 M/s) |
| Patricia trie | **113 ms** | **1.68 M** | **90 MiB** | 210 ns (4.8 M/s) |

The VRP set is dense, so path compression removes only 30% of nodes, and Patricia pays for full key
comparisons at valued nodes. The binary trie stays the production index (lookups are the hot path);
Patricia is kept for workloads where memory or build time matter more.

Two optimizations measured along the way: replacing a byte loop with two 64-bit XOR +
count-leading-zero compares, and skipping comparisons at Patricia glue nodes, together cut ROV from
~370 ns to ~170 ns per route.

## 5. Robustness

- libFuzzer runs the MRT decoder for 2 minutes in every CI run (≈17 M inputs per run, ASan + UBSan).
- A mutation test (50 K corrupted records) runs in the unit tests under ASan + UBSan.
