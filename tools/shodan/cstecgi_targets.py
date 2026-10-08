#!/usr/bin/env python3
"""
Find Tenda/Realtek router models that ship the cstecgi dispatcher but have
no CVE naming them.

Every one of the 40 cstecgi advisories names TOTOLINK, and EX1800T accounts
for 18 of them. That is the most-scrutinised corner of the SDK and the worst
place to look for something new.

The SDK is white-label: cstecgi.cgi is a Realtek SDK component that many
vendors rebrand with no code changes. A vendor shipping the dispatcher with
no advisory naming it is a candidate 0-day, because nobody has reported it.

This builds the candidate list by querying NVD for each vendor's known
products and subtracting the vendors that already appear in the cluster.
Output is a hypothesis list to test by extracting firmware, not a conclusion.

    python3 cstecgi_targets.py
"""
from __future__ import annotations

import collections
import json
import re
import time
import urllib.error
import urllib.request

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "Mozilla/5.0 (research; static CVE triage)"

# Already named by an advisory in the cluster. Everything here is deprioritised.
KNOWN = {"totolink", "tplink"}


def get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"_err": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"_err": f"{type(e).__name__}"}


def main() -> int:
    print("=== which vendors ship cstecgi, per NVD descriptions ===\n")
    d = get(f"{NVD}?keywordSearch=cstecgi&resultsPerPage=100")
    if "_err" in d:
        print("query failed:", d["_err"])
        return 1

    named: collections.Counter[str] = collections.Counter()
    for v in d.get("vulnerabilities", []):
        for dd in v["cve"].get("descriptions", []):
            if dd.get("lang") != "en":
                continue
            t = dd.get("value", "")
            for m in re.finditer(r"\b([A-Z][A-Za-z]{2,12}(?:link|net|com|WiFi|net))\b", t):
                named[m.group(1).lower()] += 1
            if "TOTOLINK" in t.upper():
                named["totolink"] += 1

    print("vendors appearing in this cluster:")
    for n, c in named.most_common(12):
        print(f"  {c:3}  {n}")

    print("\n=== candidate vendors: Realtek SDK rebadges with no cstecgi CVE ===")
    print("(searching NVD per vendor for router CVEs, then checking whether")
    print(" cstecgi.cgi appears in any of their advisories)\n")

    # Realtek SDK is widely rebrand. These are the vendors most likely to
    # ship it unchanged. Each is probed for cstecgi presence.
    candidates = [
        "Zyxel", "Mercusys", "TP-Link", "D-Link", "Edimax", "Asus", "Netgear",
        "Tenda", "Comtrend", "Conexant", "Alpha", "Arris", "Sagemcom",
        "Technicolor", " Vodafone", "Orange", "Bell", "Aastra", "Draytek",
        "Loop", "Four-Faith", "Suncomm", "Cudy", "Mimosa", "Ovascom",
    ]

    found, absent = [], []
    for vendor in candidates:
        q = urllib.parse.quote(vendor)
        r = get(f"{NVD}?keywordSearch={q}%20cgi&resultsPerPage=40")
        if "_err" in r:
            continue
        blob = json.dumps(r).lower()
        has_cste = "cstecgi" in blob
        entry = (vendor, r.get("totalResults", 0))
        (found if has_cste else absent).append(entry)
        time.sleep(0.6)  # stay under the NVD rate limit

    print("vendors WITH cstecgi in their advisories (already known):")
    for v, n in found:
        print(f"  {v:14} {n} cgi-related CVEs")
    print("\nvendors with router CGI CVEs but NO cstecgi mention (candidates):")
    for v, n in absent:
        if n:
            print(f"  {v:14} {n} cgi-related CVEs")

    print("\nNOTE: this is a prioritisation list, not a finding. A vendor")
    print("appearing here has not been shown to ship cstecgi.cgi. Each must")
    print("be confirmed by pulling its firmware and looking for the")
    print("dispatcher, and then diffed against a patched TOTOLINK build.")
    return 0


if __name__ == "__main__":
    import urllib.parse  # noqa: E402  (used above)
    raise SystemExit(main())