#!/usr/bin/env python3
"""
Map which vendors ship the Realtek cstecgi CGI dispatcher.

The cluster is large and every public advisory names only the vendor that
happened to get reported first. The SDK is white-label, so other rebadges
almost certainly ship the same cstecgi.cgi. Those unlisted vendors are the
interesting surface: a firmware image with the same dispatcher may be
unpatched even when the named vendor's advisory says otherwise.

Output is a vendor list with counts, derived from NVD reference URLs, so
the provenance of each name is visible rather than asserted.

    python3 cstecgi_map.py
"""
from __future__ import annotations

import collections
import json
import re
import time
import urllib.error
import urllib.request

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "Mozilla/5.0 (research; static CVE correlation)"


def get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"_err": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"_err": f"{type(e).__name__}: {e}"}


def main() -> int:
    d = get(f"{NVD}?keywordSearch=cstecgi&resultsPerPage=200")
    if "_err" in d:
        print("NVD query failed:", d["_err"])
        return 1

    total = d.get("totalResults", 0)
    print(f"NVD keywordSearch=cstecgi -> {total} CVEs\n")

    # map CVE -> (vendors named in descriptions, reference hosts)
    vendor_rx = re.compile(r"\b([A-Z][A-Za-z0-9+]{1,15}(?:\s[A-Z][A-Za-z0-9+]{1,15})?)\s+"
                           r"(?:wireless\s+routers?|routers?|gateways?|cameras?|NVRs?|DVRs?)\b")
    host_counts: collections.Counter[str] = collections.Counter()
    per_cve: list[tuple[str, str, int]] = []

    for v in d.get("vulnerabilities", []):
        c = v["cve"]
        desc = ""
        for dd in c.get("descriptions", []):
            if dd.get("lang") == "en":
                desc = dd.get("value", "")
                break
        named = set()
        for m in vendor_rx.finditer(desc):
            named.add(m.group(1).strip())
        for r in c.get("references", []):
            u = r.get("url", "")
            mh = re.search(r"github\.com/([^/]+)/([^/?#]+)", u)
            if mh:
                host_counts[mh.group(1)] += 1
        per_cve.append((c["id"], "; ".join(sorted(named)) or "(none named)", len(c.get("references", []))))

    print("=== vendors named in the advisory text ===")
    named_count: collections.Counter[str] = collections.Counter()
    for cid, names, _ in per_cve:
        for nm in names.split("; "):
            if nm != "(none named)":
                named_count[nm] += 1
    for nm, n in named_count.most_common(40):
        print(f"  {n:3}  {nm}")

    print("\n=== GitHub owners appearing in reference URLs ===")
    for h, n in host_counts.most_common(30):
        print(f"  {n:3}  {h}")

    print("\n=== newest 12 by published date ===")
    def pub(cid: str) -> str:
        for v in d["vulnerabilities"]:
            if v["cve"]["id"] == cid:
                return v["cve"].get("published", "")
        return ""
    for cid, names, _ in sorted(per_cve, key=lambda x: pub(x[0]), reverse=True)[:12]:
        print(f"  {pub(cid)[:10]}  {cid:18} {names}")

    print("\nNOTE: a vendor absent from this list is not necessarily safe.")
    print("It means no advisory has named it, which is the hypothesis to test,")
    print("not a conclusion. Confirm by extracting its firmware and diffing")
    print("the dispatcher against a patched build.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())