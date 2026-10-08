"""NVD API 2.0 ingestion worker - keeps the `cves` table in sync.

Run as a cron job / Celery beat task. Incremental: tracks last-modified
timestamp in a state file and only pulls changes since the last successful run.

    python -m ingest.nvd_sync            # incremental since last run
    python -m ingest.nvd_sync --backfill # from scratch (rate-limited, slow)
"""
from __future__ import annotations

import argparse
import os
import time
from datetime import datetime, timezone, timedelta

import psycopg
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
STATE_DIR = os.environ.get("STATE_DIR", ".state")
STATE_FILE = os.path.join(STATE_DIR, "nvd_last_mod.txt")
PAGE_SIZE = 200
WITHOUT_KEY_RPS_SLEEP = 6  # NVD: 5 requests / 30s without an API key


def _db():
    return psycopg.connect(
        dbname=os.environ.get("DB_NAME", "leviathan"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASS", "postgres"),
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432"),
        autocommit=False,
    )


def _load_state() -> datetime | None:
    try:
        with open(STATE_FILE) as fh:
            return datetime.fromisoformat(fh.read().strip())
    except (OSError, ValueError):
        return None


def _save_state(dt: datetime) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as fh:
        fh.write(dt.isoformat())


def _extract(row: dict) -> tuple | None:
    cve = row.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), None)

    cvss = None
    severity = None
    metrics = cve.get("metrics", {})
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            cvss = data.get("baseScore")
            severity = (data.get("baseSeverity")
                        or entries[0].get("baseSeverity"))
            break

    cpe_matches = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if match.get("criteria"):
                    cpe_matches.append(match["criteria"])

    published = cve.get("published")
    modified = cve.get("lastModified")

    return (
        cve_id, desc, cvss, severity, cpe_matches,
        published, modified,
    )


def _upsert(conn: psycopg.Connection, rows: list[tuple]) -> int:
    saved = 0
    with conn.cursor() as cur:
        for r in rows:
            (cve_id, desc, cvss, severity, cpe_matches, published, modified) = r
            cur.execute(
                """
                INSERT INTO cves (cve_id, description, cvss, severity,
                                  cpe_matches, published, modified)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    description = COALESCE(EXCLUDED.description, cves.description),
                    cvss        = COALESCE(EXCLUDED.cvss, cves.cvss),
                    severity    = COALESCE(EXCLUDED.severity, cves.severity),
                    cpe_matches = COALESCE(EXCLUDED.cpe_matches, cves.cpe_matches),
                    modified    = COALESCE(EXCLUDED.modified, cves.modified),
                    updated_at  = now();
                """,
                (cve_id, desc, cvss, severity,
                 psycopg.Json(cpe_matches) if cpe_matches else None,
                 published, modified),
            )
            saved += 1
    conn.commit()
    return saved


def sync(backfill: bool = False) -> int:
    api_key = os.environ.get("NVD_API_KEY")  # recommended: avoids rate limits
    headers = {"apiKey": api_key} if api_key else {}

    start_idx = 0
    total = 0
    session = requests.Session()
    session.headers.update(headers)

    params: dict = {"resultsPerPage": PAGE_SIZE}
    if not backfill:
        last = _load_state()
        # NVD rejects ranges > 120 days; fall back to 7-day window on stale state
        if last and datetime.now(timezone.utc) - last <= timedelta(days=110):
            params["lastModStartDate"] = last.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000")

    while True:
        params["startIndex"] = start_idx
        resp = session.get(NVD_URL, params=params, timeout=60)
        if resp.status_code == 403:
            print("NVD rate limited; sleeping 30s")
            time.sleep(30)
            continue
        if resp.status_code != 200:
            print(f"NVD fetch failed: HTTP {resp.status_code}")
            break

        payload = resp.json()
        results = payload.get("vulnerabilities", [])
        if not results:
            break

        rows = [r for r in (_extract(x) for x in results) if r]
        with _db() as conn:
            total += _upsert(conn, rows)

        total_results = payload.get("totalResults", 0)
        start_idx += payload.get("resultsPerPage", PAGE_SIZE)
        if start_idx >= total_results:
            break
        time.sleep(0.7 if api_key else WITHOUT_KEY_RPS_SLEEP)

    _save_state(datetime.now(timezone.utc))
    return total


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--backfill", action="store_true",
                    help="full sync from scratch (slow without API key)")
    args = ap.parse_args()
    n = sync(backfill=args.backfill)
    print(f"NVD sync complete: {n} CVEs upserted")
