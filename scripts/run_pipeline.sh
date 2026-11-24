#!/usr/bin/env bash
# Runs the three-agent pipeline end to end and prints each agent's summary.
#
#   scripts/run_pipeline.sh <bin-dir> <vrps.csv> <aspas.csv> <input.mrt> [rate]
#
# rate = replay speed in updates/s (0 or omitted = as fast as possible).
# Agent summaries (including latency percentiles) go to stderr; alerts for
# failing routes go to results/raw/alerts.txt.
set -euo pipefail
bin=${1:?bin dir}
vrps=${2:?vrps.csv}
aspas=${3:?aspas.csv}
input=${4:?input.mrt}
rate=${5:-0}
slots=${SLOTS:-2097152}
ring=${RING:-1048576}

cd "$(dirname "$0")/.."
mkdir -p results/raw
rm -f /dev/shm/rg.routes /dev/shm/rg.verdicts

# Create the routes table first so the consumers can attach before data flows.
"$bin/routeguard-ingest" --create-only --slots "$slots" --ring "$ring"
"$bin/routeguard-validator" --vrps "$vrps" --aspas "$aspas" --ring "$ring" --exit-when-idle-ms 3000 &
validator=$!
"$bin/routeguard-alert" --exit-when-idle-ms 3000 > results/raw/alerts.txt &
alert=$!

# Wait until the validator has loaded the RPKI data and created rg.verdicts.
for _ in $(seq 1 600); do
  [[ -e /dev/shm/rg.verdicts ]] && break
  sleep 0.05
done
sleep 0.5

"$bin/routeguard-ingest" --mrt "$input" --slots "$slots" --ring "$ring" --rate "$rate"
wait "$validator" "$alert"
echo "alerts written: $(wc -l < results/raw/alerts.txt)" >&2
rm -f /dev/shm/rg.routes /dev/shm/rg.verdicts
