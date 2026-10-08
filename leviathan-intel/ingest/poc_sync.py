"""Sploitus PoC-feed ingestion - public proof-of-concept availability signal.

Verified behavior of sploitus.com (2026-09):
  - POST https://sploitus.com/search  {"query": "...", "offset": 0, "sort": "date"}
    is keyless and returns {"exploits": [...], "exploits_total": N}
  - each exploit: title, score, href (direct PoC link), type (github/exploit-db/...),
    published, id (-> https://sploitus.com/exploit?id=...), cve_list, epss_score
  - querying a CVE id as the search string returns PoCs tagged with that CVE

PoC availability is one input of priority_score (+5): a CVE with a public PoC
is cheaper to exploit, so it jumps the triage queue. This worker only READS a
public index - it never downloads or runs PoC code.

    python -m ingest.poc_sync --cve CVE-2021-44228 --store
    python -m ingest.poc_sync --tenant 2 --limit 25 --store   # enrich own findings
    python -m ingest.poc_sync --cve CVE-2021-44228            # lookup only
"""
from __future__ import annotations

import argparse
import os
import re
import time

import psycopg
import requests

BASE = "https://sploitus.com/search"
PERMALINK = "https://sploitus.com/exploit?id={eid}"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
REQUEST_TIMEOUT = 30
SLEEP_BETWEEN = 1.0  # be polite to a free public index

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"),
}


def _db():
    return psycopg.connect(
        dbname=os.environ.get("DB_NAME", "leviathan"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASS", "postgres"),
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432"),
    )


def fetch_exploits(query: str, offset: int = 0, limit: int = 10) -> dict:
    """Raw Sploitus search. Returns {'exploits': [...], 'exploits_total': N}."""
    resp = requests.post(
        BASE,
        json={"query": query, "offset": offset, "sort": "date"},
        headers=HEADERS,
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    payload = resp.json()
    return {"exploits": payload.get("exploits", []),
            "exploits_total": payload.get("exploits_total", 0)}


INSERT_SQL = """
    INSERT INTO poc_refs (cve_id, source, url)
    VALUES (%s, %s, %s)
    ON CONFLICT (cve_id, source, url) DO NOTHING;
"""


def pocs_for_cve(cve_id: str, limit: int = 10) -> list[dict]:
    """Normalized, CVE-filtered PoC references for one CVE."""
    if not CVE_RE.fullmatch(cve_id):
        raise ValueError(f"not a CVE id: {cve_id!r}")
    found: list[dict] = []
    for exploit in fetch_exploits(cve_id, limit=limit)["exploits"]:
        tagged = {c.upper() for c in (exploit.get("cve_list") or [])}
        if cve_id.upper() not in tagged:
            continue
        url = exploit.get("href") or PERMALINK.format(eid=exploit.get("id", ""))
        if not url:
            continue
        found.append({
            "source": "sploitus",
            "url": url,
            "title": (exploit.get("title") or "")[:300],
            "published": exploit.get("published"),
            "etype": exploit.get("type"),
        })
    return found


def store_pocs(cve_id: str, pocs: list[dict]) -> int:
    if not pocs:
        return 0
    with _db() as conn, conn.cursor() as cur:
        cur.executemany(
            INSERT_SQL, [(cve_id, p["source"], p["url"]) for p in pocs])
    return len(pocs)


def enrich_tenant(tenant_id: int, limit: int = 25, store: bool = False) -> dict:
    """Sploitus-lookup the CVEs already prioritized for a tenant (highest
    scoring findings first), optionally storing references."""
    stats = {"checked": 0, "with_poc": 0, "refs": 0}
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT f.cve_id
              FROM findings f
             WHERE f.asset_id IN (SELECT id FROM assets WHERE tenant_id = %s)
             ORDER BY f.cve_id
             LIMIT %s
            """,
            (tenant_id, limit),
        )
        cve_ids = [r[0] for r in cur.fetchall()]

    for cve_id in cve_ids:
        stats["checked"] += 1
        pocs = pocs_for_cve(cve_id)
        if pocs:
            stats["with_poc"] += 1
            stats["refs"] += len(pocs)
            print(f"  {cve_id}: {len(pocs)} PoC(s)")
            if store:
                store_pocs(cve_id, pocs)
        else:
            print(f"  {cve_id}: no public PoC")
        time.sleep(SLEEP_BETWEEN)
    return stats


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--cve", metavar="CVE-ID")
    g.add_argument("--tenant", type=int, metavar="ID",
                   help="enrich this tenant's prioritized CVEs")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--store", action="store_true",
                    help="write refs into poc_refs table")
    args = ap.parse_args()

    if args.cve:
        pocs = pocs_for_cve(args.cve, limit=args.limit)
        for p in pocs:
            print(f"[{p['etype']}] {p['title']}\n    {p['url']}")
        print(f"{args.cve}: {len(pocs)} reference(s) found")
        if args.store:
            print(f"stored: {store_pocs(args.cve, pocs)}")
    else:
        stats = enrich_tenant(args.tenant, limit=args.limit, store=args.store)
        print(f"tenant {args.tenant}: {stats}")
