#!/usr/bin/env bash
# Download one hour of raw BGP UPDATE messages (MRT format) from a RIPE RIS
# route collector. Files are published every 5 minutes.
#
#   scripts/fetch_ris_updates.sh 2026-11-23 12 rrc00
#
# Output: data/ris/updates.YYYYMMDD.HHMM.gz (12 files)
set -euo pipefail

date_arg=${1:?usage: fetch_ris_updates.sh YYYY-MM-DD HOUR [collector]}
hour=$(printf '%02d' "${2:?hour required}")
collector=${3:-rrc00}

ymd=${date_arg//-/}
ym=${date_arg:0:4}.${date_arg:5:2}
out_dir="$(dirname "$0")/../data/ris"
mkdir -p "$out_dir"

for minute in 00 05 10 15 20 25 30 35 40 45 50 55; do
  name="updates.${ymd}.${hour}${minute}.gz"
  url="https://data.ris.ripe.net/${collector}/${ym}/${name}"
  if [[ -s "$out_dir/$name" ]]; then
    echo "have $name"
    continue
  fi
  echo "fetch $url"
  curl -fsS --retry 3 -o "$out_dir/$name" "$url"
done
ls -la "$out_dir"
