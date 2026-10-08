"""CISA KEV ingestion - flags CVEs that are confirmed exploited in the wild.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Run frequently (hourly): KEV additions are the strongest prioritization signal.
"""
from __future__ import annotations

import os
from datetime import date

import psycopg
import requests

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


def _db():
    return psycopg.connect(
        dbname=os.environ.get("DB_NAME", "leviathan"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASS", "postgres"),
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432"),
    )


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def sync() -> tuple[int, int]:
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    entries = resp.json().get("vulnerabilities", [])

    flagged = missing = 0
    with _db() as conn, conn.cursor() as cur:
        for e in entries:
            cve_id = e.get("cveID")
            if not cve_id:
                continue
            cur.execute(
                """
                UPDATE cves
                   SET kev = TRUE,
                       kev_date = COALESCE(%s, kev_date),
                       updated_at = now()
                 WHERE cve_id = %s
                """,
                (_parse_date(e.get("dateAdded")), cve_id),
            )
            if cur.rowcount:
                flagged += 1
            else:
                missing += 1  # CVE not yet ingested from NVD; next NVD run + re-run fixes
    return flagged, missing


if __name__ == "__main__":
    flagged, missing = sync()
    print(f"KEV sync: {flagged} CVEs flagged, {missing} not-yet-in-NVD (rerun after nvd_sync)")
