#!/usr/bin/env bash
# Integration test: three agent processes over the shared-memory store.
#   tests/pipeline_test.sh <bin-dir> <data-dir>
set -euo pipefail
bin=${1:?bin dir}
data=${2:?data dir}
tag="rgpipe.$$"
routes="$tag.routes"
verdicts="$tag.verdicts"
out=$(mktemp -d)
cleanup() { rm -rf "$out"; rm -f "/dev/shm/$routes" "/dev/shm/$verdicts"; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

"$bin/routeguard-ingest" --table "$routes" --create-only --slots 64 --ring 64 2> /dev/null
"$bin/routeguard-validator" --vrps "$data/sample_roas.csv" --in "$routes" --out "$verdicts" \
  --ring 64 --exit-when-idle-ms 700 2> "$out/validator.err" &
validator=$!
for _ in $(seq 1 100); do [[ -e "/dev/shm/$verdicts" ]] && break; sleep 0.02; done
"$bin/routeguard-alert" --in "$verdicts" --exit-when-idle-ms 700 > "$out/alerts.txt" 2> "$out/alert.err" &
alert=$!
sleep 0.2

"$bin/routeguard-ingest" --table "$routes" --slots 64 --ring 64 --updates "$data/sample_updates.txt" 2> "$out/ingest1.err"
wait "$validator" "$alert"

# The store holds state, not an event log: updates to one slot that land
# faster than the validator reacts are coalesced. The sample's 1.1.1.0/24
# hijack is withdrawn microseconds later, so it may or may not be seen; the
# three routes that are still invalid in the final state must be.
for prefix in 192.0.2.0/25 203.0.113.0/24 2001:db8::/32; do
  grep -q "rov=INVALID.*$prefix" "$out/alerts.txt" || { cat "$out"/*; fail "no alert for $prefix"; }
done
grep -q 'end-to-end latency' "$out/alert.err" || fail "alert printed no latency summary"

# Restart: a second ingest must rebuild its index from the table (6 live
# routes: 1.1.1.0/24 was withdrawn), not start from scratch.
"$bin/routeguard-ingest" --table "$routes" --slots 64 --ring 64 --updates /dev/null 2> "$out/ingest2.err"
grep -q 'rebuilt 6 keys' "$out/ingest2.err" || { cat "$out/ingest2.err"; fail "ingest did not rebuild its index"; }

# A validator started after the data is already there converges via its initial scan.
"$bin/routeguard-validator" --vrps "$data/sample_roas.csv" --in "$routes" --out "$verdicts" \
  --ring 64 --exit-when-idle-ms 1 2> "$out/validator2.err" &
sleep 0.5
kill -TERM $! 2> /dev/null || true
wait $! 2> /dev/null || true
grep -q 'initial scan validated 6' "$out/validator2.err" || { cat "$out/validator2.err"; fail "late validator did not converge"; }

echo "pipeline test passed"
