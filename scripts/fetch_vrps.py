#!/usr/bin/env python3
"""Download the current global VRP set and write it as routeguard CSV.

Source: the public rpki-client console (https://console.rpki-client.org/),
which publishes the validated ROA payloads as JSON. Standard library only.

    python3 scripts/fetch_vrps.py data/vrps.csv

To get BGP updates to validate, download an MRT update file from RIPE RIS
(https://data.ris.ripe.net/rrc00/) and convert it with bgpdump:

    bgpdump -m updates.20261117.0000.gz > data/updates.txt
"""

import csv
import json
import sys
import urllib.request

URL = "https://console.rpki-client.org/vrps.json"


def main() -> int:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "data/vrps.csv"
    req = urllib.request.Request(URL, headers={"User-Agent": "routeguard-fetch/0.1"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        doc = json.load(resp)

    roas = doc.get("roas", [])
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ASN", "IP Prefix", "Max Length", "Trust Anchor"])
        for r in roas:
            asn = str(r["asn"])
            if not asn.upper().startswith("AS"):
                asn = "AS" + asn
            w.writerow([asn, r["prefix"], r["maxLength"], r.get("ta", "")])

    print(f"wrote {len(roas)} VRPs to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
