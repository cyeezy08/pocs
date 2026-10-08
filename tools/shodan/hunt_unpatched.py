#!/usr/bin/env python3
"""
Find recent CVEs that reference public exploit PoCs but have no vendor advisory.

The cstecgi work showed most advisories name no vendor at all. That is a
search opportunity, not a dead end: a CVE whose only references are
individual researchers' GitHub PoCs means there is no coordinated advisory,
so there is no patch guidance and the vendor may not even know. Those are
the CVEs worth re-testing to see whether the fix ever shipped.

This is corpus triage, not exploitation. Nothing here touches a device.

    python3 hunt_unpatched.py [--days N] [--keyword K]
"""
from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.request

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "Mozilla/5.0 (research; static CVE triage)"


def get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"_err": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"_err": f"{type(e).__name__}: {e}"}


def days_ago_iso(n: int) -> str:
    """NVD 2.0 wants ISO8601 with an explicit Z, and caps the window at 120 days."""
    n = min(n, 119)
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - n * 86400))


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def classify(refs: list[dict]) -> tuple[bool, bool, list[str]]:
    """(has_github_poc, has_vendor_advisory, github_urls)."""
    gh, vendor = [], False
    for r in refs:
        u = r.get("url", "")
        if "github.com" in u:
            gh.append(u)
        if any(d in u for d in ("security-advisories", "psirt", ".security.", "/advisories/")):
            vendor = True
    return bool(gh), vendor, gh


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=120)
    ap.add_argument("--keyword", default="")
    args = ap.parse_args()

    since = days_ago_iso(args.days)
    base = f"{NVD}?pubStartDate={since}&pubEndDate={now_iso()}"
    if args.keyword:
        base += f"&keywordSearch={args.keyword}"
    base += "&resultsPerPage=2000"

    print(f"window : last {args.days} days")
    if args.keyword:
        print(f"filter : {args.keyword}")
    print(f"query  : {base[:110]}...\n")

    d = get(base)
    if "_err" in d:
        print("query failed:", d["_err"])
        return 1

    total = d.get("totalResults", 0)
    print(f"total CVEs: {total}\n")

    interesting = []
    for v in d.get("vulnerabilities", []):
        c = v["cve"]
        refs = c.get("references", [])
        has_poc, has_vendor, gh = classify(refs)
        desc = ""
        for dd in c.get("descriptions", []):
            if dd.get("lang") == "en":
                desc = dd.get("value", "")
                break

        metrics = c.get("metrics", {})
        score = ""
        cvss = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV40") or metrics.get("cvssMetricV31")
        if cvss:
            try:
                score = str(cvss[0]["cvssData"].get("baseScore"))
            except Exception:  # noqa: BLE001
                score = ""

        # interesting: public PoC, no vendor advisory, and RCE-flavoured text
        rce = bool(re.search(r"\b(remote code execution|rce|command injection|unauthenticated|auth bypass|pre-auth)\b", desc, re.I))
        if has_poc and not has_vendor and rce:
            interesting.append(
                (c["id"], c.get("published", "")[:10], score, has_poc, desc[:110], gh[:2])
            )

    print(f"=== public PoC + no vendor advisory + RCE/auth-flavoured: {len(interesting)} ===\n")
    for cid, pub, score, _poc, desc, gh in interesting[:45]:
        print(f"  {cid:18} {pub}  cvss={score or '?':4}  {desc}")
        for g in gh:
            print(f"      {g}")
    if not interesting:
        print("  none in this window; widen --days or add --keyword")

    print("\nNOTE: absence of an advisory is not evidence the bug is unpatched.")
    print("It is a prioritisation signal: those are the CVEs where a re-test")
    print("is most likely to learn something new, because nobody has asked")
    print("the vendor whether they fixed it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())