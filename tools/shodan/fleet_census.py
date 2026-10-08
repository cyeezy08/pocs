#!/usr/bin/env python3
"""
fleet_census.py - measure the DEPLOYED firmware-version distribution of a
device family, not just "how many hosts match a CVE".

The premise: a single CVE + a host count is a saturated output that everyone
produces. What almost nobody produces is a patch-state map - which specific
firmware builds are actually deployed, in what numbers, and whether each one
still ships a binary that is byte-identical to a known-vulnerable one.

That requires three things most people only have one of:
    Shodan query credits      -> what is deployed, at what scale
    a firmware extraction path -> what is inside each build
    NVD lookups               -> which auth-bypass maps to which build

Credit discipline
-----------------
Shodan facets return aggregate counts alongside the first result page, so a
whole distribution costs ONE search instead of one search per value. This tool
is therefore facet-first and never paginates: it will not burn 200k credits
doing what 20 queries can do.

Passive only
------------
This reads Shodan's index. It does not resolve, connect to, scan or probe any
host. The scan API is deliberately not implemented. Shodan's own guidance:
observe rather than interact.

Usage
-----
    export SHODAN_API_KEY=...      # never paste the key into chat
    python3 fleet_census.py --query 'product:Dahua' --facets version,country
    python3 fleet_census.py --preset dahua
    python3 fleet_census.py --preset dahua --json out.json

No key present is a clean, explained failure rather than a traceback.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.shodan.io"
UA = "Mozilla/5.0 (authorized passive research)"

# Queries that describe a device family rather than a specific bug. Kept as
# presets so the same census can be re-run against the whole field later and
# compared, which is what makes it a measurement rather than a snapshot.
PRESETS = {
    "dahua": {
        "query": 'product:"Dahua"',
        "facets": "version,country,org,port",
        "note": "Dahua device family. Cross-reference versions against "
                "CVE-2021-33044 (auth bypass) and the sonia exec sinks.",
    },
    "dahua-web": {
        "query": 'product:"Dahua" http.title:"WEB SERVICE"',
        "facets": "version,country",
        "note": "Dahua web interfaces only - the surface the exec sinks sit on.",
    },
    "hikvision": {
        "query": 'product:"Hikvision"',
        "facets": "version,country,org",
        "note": "Nearest competitor; useful as a control for whether a finding "
                "is Dahua-specific or SDK-wide.",
    },
    "cstecgi": {
        "query": '"cstecgi"',
        "facets": "product,version,country",
        "note": "Realtek cstecgi dispatcher. Every public CVE names TOTOLINK; "
                "any other product appearing here is an unlisted rebadge and "
                "therefore unexamined.",
    },
}


def api_key() -> str:
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        print("SHODAN_API_KEY is not set.\n", file=sys.stderr)
        print("Set it locally so it never enters a transcript or a repo:", file=sys.stderr)
        print("    export SHODAN_API_KEY='...'", file=sys.stderr)
        print("    # or append it to /root/.hermes/.env", file=sys.stderr)
        sys.exit(2)
    return key


def get(path: str, params: dict, key: str, tries: int = 3) -> dict:
    """GET with backoff. Shodan rate-limits at 1 req/s on most plans."""
    params = {**params, "key": key}
    url = f"{API}/{path.lstrip('/')}?{urllib.parse.urlencode(params)}"
    for attempt in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:300]
            if e.code == 401:
                return {"_error": "401 - API key rejected"}
            if e.code == 403:
                return {"_error": f"403 - plan does not permit this query: {body}"}
            if e.code == 429:
                time.sleep(2 ** attempt)
                continue
            return {"_error": f"HTTP {e.code}: {body}"}
        except Exception as e:  # noqa: BLE001
            if attempt == tries - 1:
                return {"_error": f"{type(e).__name__}: {e}"}
            time.sleep(2 ** attempt)
    return {"_error": "retries exhausted"}


def credit_balance(key: str) -> dict:
    """Read remaining credits first. A census should never surprise the quota."""
    return get("api-info", {}, key)


def census(query: str, facets: str, key: str) -> dict:
    # One search, no pagination: facets carry the distribution.
    params = {"query": query, "facets": facets, "minify": "true"}
    res = get("shodan/host/search", params, key)
    if "_error" in res:
        return res
    out = {
        "query": query,
        "total": res.get("total"),
        "facets": {},
    }
    for f in res.get("facets", {}):
        out["facets"][f.get("name", "?")] = [
            {"value": v.get("value"), "count": v.get("count")}
            for v in f.get("facets", [])
        ]
    return out


def show(c: dict) -> None:
    print(f"query : {c['query']}")
    print(f"total : {c['total']:,} hosts\n" if isinstance(c.get("total"), int)
          else f"total : {c.get('total')}\n")
    for name, items in c.get("facets", {}).items():
        print(f"=== {name} ===")
        for it in items[:30]:
            val = (it["value"] or "(none)").replace("\n", " ")[:64]
            print(f"  {it['count']:>9,}  {val}")
        if len(items) > 30:
            print(f"  ... {len(items) - 30} more")
        print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--preset", choices=sorted(PRESETS))
    ap.add_argument("--query")
    ap.add_argument("--facets", default="version,country,org")
    ap.add_argument("--json", help="also write raw output here")
    ap.add_argument("--no-credits", action="store_true",
                    help="skip the credit-balance read")
    args = ap.parse_args()

    if not args.preset and not args.query:
        ap.error("give --preset or --query")

    key = api_key()

    if not args.no_credits:
        info = credit_balance(key)
        if "_error" in info:
            print(f"credit check failed: {info['_error']}", file=sys.stderr)
            print("continuing anyway - the census itself will report its own errors\n",
                  file=sys.stderr)
        else:
            plan = info.get("plan", "?")
            print(f"plan: {plan}")
            for k in ("query_credits", "scan_credits", "monitored_ips"):
                if k in info:
                    print(f"  {k}: {info[k]}")
            print()

    if args.preset:
        p = PRESETS[args.preset]
        print(f"# {p['note']}\n")
        c = census(p["query"], p["facets"], key)
    else:
        c = census(args.query, args.facets, key)

    if "_error" in c:
        print(f"ERROR: {c['_error']}", file=sys.stderr)
        return 1

    show(c)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(c, f, indent=2)
        print(f"raw written to {args.json}")

    print("NOTE: this is a count, not a reachability claim. A version appearing")
    print("here is not proof that a given code path is reachable. Pair it with")
    print("the firmware diff before writing anything as a finding.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
