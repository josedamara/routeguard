# RouteGuard

A BGP route-security monitor written in C++20 for Linux. It checks live BGP announcements against RPKI and
(eventually) ASPA, and flags hijacks and route leaks. It is structured as independent agents that share
state through shared memory, the way agents share state in a state-based network OS.

## Why

- RPKI Route Origin Validation now covers about two-thirds of announced prefixes, but it only checks
  **who originates** a route, not **the path it took**. Route leaks and forged-origin hijacks pass it.
- ASPA (path validation) closes that gap, but only about 2.5% of ASes publish ASPA records so far.
- Global route leaks and hijacks still happen every quarter.

RouteGuard implements both checks and runs them on real BGP data from RIPE RIS / RouteViews.

## Architecture (target)

```
 RIS / bgpdump ─▶ ingest agent ──┐
                                 ▼
 RPKI VRPs ─────▶ ┌──────────────────────────────┐ ◀── validator agent (ROV + ASPA)
                  │  shared-memory state store   │ ◀── FIB agent (longest-prefix match)
                  │  (seqlock slots + change ring)│ ──▶ alert agent (stdout / JSON / webhook)
                  └──────────────────────────────┘
```

Each agent is its own process. Any agent can be killed and restarted without losing state.

## Roadmap

| Stage | What | Status |
|---|---|---|
| 1 | `Prefix`, binary prefix trie, RFC 6811 ROV, `bgpdump -m` parser, CLI | ✅ done |
| 2 | Shared-memory state store (`include/routeguard/state/state_store.hpp`) | ⬜ interface only |
| 3 | Split into agents over the store, crash/restart recovery | ⬜ |
| 4 | ASPA upstream/downstream verification + valley-free leak heuristics, live RIS feed | ⬜ `check_hop` done |
| 5 | Patricia-trie compression, benchmarks (updates/sec, p99 latency), fuzzing | ⬜ |

## Build and run (Linux / WSL)

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DROUTEGUARD_SANITIZE=ON
cmake --build build
ctest --test-dir build --output-on-failure
./build/routeguard --roas data/sample_roas.csv --updates data/sample_updates.txt --all
```

Expected output:

```
VALID      1.1.1.0/24        origin=AS13335  ...
INVALID    1.1.1.0/24        origin=AS64666  ...   # wrong origin (hijack)
INVALID    192.0.2.0/25      origin=AS64500  ...   # more specific than maxLength
VALID      198.51.100.64/26  origin=AS64501  ...
INVALID    203.0.113.0/24    origin=AS64503  ...   # AS0 ROA
VALID      2001:db8:1::/48   origin=AS64502  ...
INVALID    2001:db8::/32     origin=none     ...   # AS_SET origin
NOT_FOUND  8.8.8.0/24        origin=AS15169  ...
```

Or with Docker:

```bash
docker build -t routeguard . && docker run --rm routeguard
```

### Real data

```bash
python3 scripts/fetch_vrps.py data/vrps.csv                  # ~all global VRPs
bgpdump -m updates.20261117.0000.gz > data/updates.txt       # from data.ris.ripe.net
./build/routeguard --roas data/vrps.csv --updates data/updates.txt
```

## Layout

```
include/routeguard/   public headers (prefix, prefix_trie, rpki, bgp_update, aspa, state/)
src/                  implementation
apps/                 routeguard CLI
tests/                unit tests (tiny built-in harness, no downloads needed)
scripts/              Python helpers for fetching real data
data/                 small sample inputs
```

## Design notes

- **Prefix** is a fixed 16-byte value type with no heap allocation. It only accepts the canonical form
  (no host bits set).
- **PrefixTrie** stores its nodes in one `std::vector` and links them by index, not pointer. That gives
  contiguous memory and cheap copies, and indices still work inside a shared-memory segment (stage 2).
- **ROV** follows RFC 6811 exactly. Any matching ROA gives Valid. A route that is covered but has no
  match is Invalid. An AS0 ROA never matches. A route whose origin is an AS_SET can never be Valid.
