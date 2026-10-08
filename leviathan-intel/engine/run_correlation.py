"""Correlation runner - joins discovered assets against CVE intel and writes
explainable findings.

    python -m engine.run_correlation --tenant 2

Steps per tenant:
  1. pull assets that carry a CPE fingerprint
  2. pull CVEs whose cpe_matches reference the same vendor/product
  3. score each (asset, cve) pair with engine.scoring.priority_score
  4. upsert findings with itemized reasons
"""
from __future__ import annotations

import argparse
import os

import psycopg

from engine.correlate import asset_matches_cve
from engine.scoring import priority_score, triage_label


def _db():
    return psycopg.connect(
        dbname=os.environ.get("DB_NAME", "leviathan"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASS", "postgres"),
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432"),
    )


def _candidate_cves(cur, vendor: str, product: str, limit: int = 4000):
    """Cheap pre-filter: NVD CPE strings embed vendor/product as 3rd/4th fields."""
    needle = f":{vendor}:"
    cur.execute(
        """
        SELECT cve_id, cvss, epss, kev, cpe_matches
          FROM cves
         WHERE cpe_matches IS NOT NULL
           AND cpe_matches ? %s
         LIMIT %s
        """,
        (needle, limit),
    )
    return cur.fetchall()


def _has_poc(cur, cve_id: str) -> bool:
    cur.execute("SELECT 1 FROM poc_refs WHERE cve_id = %s LIMIT 1", (cve_id,))
    return cur.fetchone() is not None


def run(tenant_id: int) -> dict:
    stats = {"assets": 0, "candidates": 0, "matches": 0, "findings": 0}

    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, cpe FROM assets
             WHERE tenant_id = %s AND cpe IS NOT NULL
            """,
            (tenant_id,),
        )
        assets = cur.fetchall()

        for asset_id, asset_cpe in assets:
            stats["assets"] += 1
            from engine.correlate import parse_cpe

            parsed = parse_cpe(asset_cpe)
            if not parsed:
                continue

            cves = _candidate_cves(cur, parsed["vendor"], parsed["product"])
            stats["candidates"] += len(cves)

            for cve_id, cvss, epss, kev, cpe_matches in cves:
                matched, _reason = asset_matches_cve(asset_cpe, cpe_matches or [])
                if not matched:
                    continue
                stats["matches"] += 1

                score, reasons = priority_score(
                    cvss=cvss,
                    epss=epss,
                    kev=bool(kev),
                    public_poc=_has_poc(cur, cve_id),
                )
                reasons.append(triage_label(score))
                cur.execute(
                    """
                    INSERT INTO findings (asset_id, cve_id, priority, reasons)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (asset_id, cve_id) DO UPDATE SET
                        priority  = EXCLUDED.priority,
                        reasons   = EXCLUDED.reasons,
                        last_seen = now();
                    """,
                    (asset_id, cve_id, score, psycopg.Json(reasons)),
                )
                stats["findings"] += 1

    return stats


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", type=int, required=True)
    args = ap.parse_args()
    print(f"correlation tenant {args.tenant}: {run(args.tenant)}")
