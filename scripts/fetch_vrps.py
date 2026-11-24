#!/usr/bin/env python3
"""Download the global RPKI data set and write it as routeguard CSV files.

Source: the public rpki-client console (https://console.rpki-client.org/),
which publishes validated ROA payloads (VRPs) and ASPA records as JSON.
Standard library only.

    python3 scripts/fetch_vrps.py                       # download + convert
    python3 scripts/fetch_vrps.py --json data/vrps.json # convert a local copy

Writes:
    data/vrps.csv   ASN,IP Prefix,Max Length,Trust Anchor
    data/aspas.csv  Customer ASN,Providers   (providers separated by spaces)
"""

import argparse
import csv
import json
import urllib.request

URL = "https://console.rpki-client.org/vrps.json"


def as_str(asn) -> str:
    s = str(asn)
    return s if s.upper().startswith("AS") else "AS" + s


def provider_asns(entry):
    # Newer rpki-client: "providers": [2914, 3356]; older: list of dicts.
    for p in entry.get("providers", entry.get("provider_set", [])):
        yield p["provider_asid"] if isinstance(p, dict) else p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="convert this local vrps.json instead of downloading")
    ap.add_argument("--vrps-out", default="data/vrps.csv")
    ap.add_argument("--aspas-out", default="data/aspas.csv")
    args = ap.parse_args()

    if args.json:
        with open(args.json) as f:
            doc = json.load(f)
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "routeguard-fetch/0.1"})
        with urllib.request.urlopen(req, timeout=300) as resp:
            doc = json.load(resp)

    roas = doc.get("roas", [])
    with open(args.vrps_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ASN", "IP Prefix", "Max Length", "Trust Anchor"])
        for r in roas:
            w.writerow([as_str(r["asn"]), r["prefix"], r["maxLength"], r.get("ta", "")])

    aspas = doc.get("aspas", [])
    with open(args.aspas_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Customer ASN", "Providers"])
        for a in aspas:
            providers = " ".join(as_str(p) for p in provider_asns(a))
            w.writerow([as_str(a["customer_asid"]), providers])

    print(f"wrote {len(roas)} VRPs to {args.vrps_out} and {len(aspas)} ASPAs to {args.aspas_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
