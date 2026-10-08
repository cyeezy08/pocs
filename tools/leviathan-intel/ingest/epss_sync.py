"""FIRST EPSS ingestion - exploitation probability per CVE (0..1).

Feed: https://epss.cyentia.com/epss_scores-current.csv.gz  (daily, no key needed)
EPSS is the best predictor of "will this actually get exploited" and carries
equal weight with CVSS in our priority score for that reason.
"""
from __future__ import annotations

import csv
import gzip
import io
import os

import psycopg
import requests

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def _db():
    return psycopg.connect(
        dbname=os.environ.get("DB_NAME", "leviathan"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASS", "postgres"),
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432"),
    )


def sync() -> int:
    resp = requests.get(EPSS_URL, timeout=120)
    resp.raise_for_status()

    with gzip.open(io.BytesIO(resp.content), mode="rt", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)                 # metadata row: model version etc.
        col_date = header[-1]                 # '2026-09-10T00:00:00+0000'
        feed_date = col_date.split("T")[0]
        next(reader)                          # column names row: cve,epss,percentile

        updated = 0
        with _db() as conn, conn.cursor() as cur:
            batch: list[tuple] = []
            for row in reader:
                if not row or len(row) < 2:
                    continue
                batch.append((row[0], row[1], feed_date))
                if len(batch) >= 5000:
                    cur.executemany(
                        """
                        UPDATE cves
                           SET epss = %s::numeric,
                               epss_date = %s::date,
                               updated_at = now()
                         WHERE cve_id = %s
                        """,
                        [(epss, d, cve) for (cve, epss, d) in batch],
                    )
                    updated += cur.rowcount
                    batch.clear()
            if batch:
                cur.executemany(
                    """
                    UPDATE cves
                       SET epss = %s::numeric,
                           epss_date = %s::date,
                           updated_at = now()
                     WHERE cve_id = %s
                    """,
                    [(epss, d, cve) for (cve, epss, d) in batch],
                )
                updated += cur.rowcount
    return updated


if __name__ == "__main__":
    n = sync()
    print(f"EPSS sync: {n} CVEs updated")
