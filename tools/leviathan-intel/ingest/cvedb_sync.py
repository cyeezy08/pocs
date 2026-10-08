"""Shodan CVEDB ingestion - bulk CVE stream + on-demand enrichment.

Verified behavior of https://cvedb.shodan.io (2026-09):
  - `/cves?limit=N` serves HUGE windows (20k+ rows in one call), newest first
  - `page`, `offset` and filter params (kev=, q=) are IGNORED server-side
  - list rows are thin: cve_id, summary, cvss, vendor/product/version,
    published - but NO epss/kev detail
  - `/cve/{id}` is rich: adds epss, kev, ransomware_campaign, propose_action
    (plain-language remediation) and references, no auth required

Therefore:
  - bulk base table     -> this worker (`--window`), daily
  - KEV authoritative   -> ingest.kev_sync (CISA feed, hourly)
  - EPSS authoritative  -> ingest.epss_sync (FIRST CSV, daily)
  - on-demand enrichment-> this worker (`--cve CVE-...`), rich record

    python -m ingest.cvedb_sync --window 20000        # daily base sync
    python -m ingest.cvedb_sync --cve CVE-2021-44228  # rich enrichment
    python -m ingest.cvedb_sync --window 20000 --dry-run

The NVD worker remains as optional backfill (full history, CPE configs);
the hot path no longer needs an NVD API key.
"""
from __future__ import annotations

import argparse
import json
import os
import time

import psycopg
import requests

BASE = "https://cvedb.shodan.io"
MAX_WINDOW = 20000
REQUEST_TIMEOUT = 180


def _db():
    return psycopg.connect(
        dbname=os.environ.get("DB_NAME", "leviathan"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASS", "postgres"),
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432"),
    )


def fetch_window(limit: int = MAX_WINDOW) -> list[dict]:
    """Single big-window pull of the newest CVE stream (filters are ignored
    server-side; see module docstring)."""
    resp = requests.get(f"{BASE}/cves", params={"limit": limit},
                        timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    payload = resp.json()
    return payload if isinstance(payload, list) else payload.get("cves", [])


def fetch_one(cve_id: str) -> dict | None:
    resp = requests.get(f"{BASE}/cve/{cve_id}", timeout=60)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _severity(cvss: float | None) -> str | None:
    if cvss is None:
        return None
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def _to_row(item: dict) -> tuple | None:
    """Map a CVEDB record onto the cves upsert row shape."""
    cve_id = item.get("cve_id")
    if not cve_id:
        return None
    description = item.get("summary")
    remediation = item.get("propose_action")

    cvss = item.get("cvss_v3") or item.get("cvss") or item.get("cvss_v2")
    try:
        cvss = round(float(cvss), 1) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None

    epss = item.get("epss")
    try:
        epss = round(float(epss), 5) if epss is not None else None
    except (TypeError, ValueError):
        epss = None

    # Synthetic CPE string so engine.correlate keeps working unchanged:
    # cvedb gives vendor/product/version triplets directly.
    vendor = (item.get("vendor") or "").strip().lower().replace(" ", "_")
    product = (item.get("product") or "").strip().lower().replace(" ", "_")
    version = (item.get("version") or "").strip()
    cpe_matches = []
    if vendor and product:
        cpe_matches.append(
            f"cpe:2.3:a:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"
        )

    return (cve_id, description, remediation, cvss, _severity(cvss),
            epss, bool(item.get("kev")), cpe_matches,
            item.get("published_time"))


UPSERT_SQL = """
    INSERT INTO cves (cve_id, description, remediation, cvss, severity,
                      epss, kev, cpe_matches, published)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::timestamptz)
    ON CONFLICT (cve_id) DO UPDATE SET
        description = COALESCE(EXCLUDED.description, cves.description),
        remediation = COALESCE(EXCLUDED.remediation, cves.remediation),
        cvss        = COALESCE(EXCLUDED.cvss, cves.cvss),
        severity    = COALESCE(EXCLUDED.severity, cves.severity),
        epss        = COALESCE(EXCLUDED.epss, cves.epss),
        kev         = cves.kev OR EXCLUDED.kev,
        cpe_matches = COALESCE(EXCLUDED.cpe_matches, cves.cpe_matches),
        published   = COALESCE(EXCLUDED.published, cves.published),
        updated_at  = now();
"""


def _upsert(rows: list[tuple]) -> int:
    if not rows:
        return 0
    with _db() as conn, conn.cursor() as cur:
        cur.executemany(UPSERT_SQL, rows)
    return len(rows)


def window_sync(limit: int = MAX_WINDOW, dry_run: bool = False) -> int:
    items = fetch_window(limit)
    rows = [r for r in (_to_row(i) for i in items) if r]
    if dry_run:
        if rows:
            print(json.dumps(rows[0][:4], ensure_ascii=False, default=str))
        return len(rows)
    return _upsert(rows)


def enrich_one(cve_id: str, dry_run: bool = False) -> bool:
    item = fetch_one(cve_id)
    if not item:
        return False
    row = _to_row(item)
    if not dry_run and row:
        _upsert([row])
    return True


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--window", type=int, metavar="N", default=None,
                   help=f"pull newest N CVEs (default {MAX_WINDOW}, daily cron)")
    g.add_argument("--cve", metavar="CVE-ID",
                   help="enrich a single CVE (rich record: epss/kev/remediation)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.cve:
        ok = enrich_one(args.cve, dry_run=args.dry_run)
        print(f"{args.cve}: {'ok' if ok else 'not found'}")
    else:
        n = window_sync(args.window or MAX_WINDOW, dry_run=args.dry_run)
        print(f"cvedb window sync: {n} rows {'seen' if args.dry_run else 'upserted'}")
