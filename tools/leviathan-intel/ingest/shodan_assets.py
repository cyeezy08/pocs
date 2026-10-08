"""Shodan asset-discovery worker - resolves each tenant's registered domains
and pulls host intel (ports, banners, product CPEs) for THEIR infrastructure.

Scope rule enforced here: only domains the tenant registered with us are ever
resolved/queried. No third-party scanning, no lead-gen probing. The Shodan
EDU key is used for passive intel on authorized assets only.

    python -m ingest.shodan_assets --tenant 2
"""
from __future__ import annotations

import argparse
import os

import psycopg
import shodan

SHODAN_KEY_ENV = "SHODAN_API_KEY"


def _db():
    return psycopg.connect(
        dbname=os.environ.get("DB_NAME", "leviathan"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASS", "postgres"),
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432"),
    )


def _upsert_asset(cur, tenant_id: int, kind: str, value: str, ip=None,
                  port=None, banner=None, cpe=None) -> None:
    cur.execute(
        """
        INSERT INTO assets (tenant_id, kind, value, ip, port, banner, cpe)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (tenant_id, kind, value) DO UPDATE SET
            ip        = COALESCE(EXCLUDED.ip, assets.ip),
            port      = COALESCE(EXCLUDED.port, assets.port),
            banner    = COALESCE(EXCLUDED.banner, assets.banner),
            cpe       = COALESCE(EXCLUDED.cpe, assets.cpe),
            last_seen = now();
        """,
        (tenant_id, kind, value, ip, port, banner, cpe),
    )


def sync_tenant(tenant_id: int) -> dict:
    key = os.environ.get(SHODAN_KEY_ENV)
    if not key:
        raise SystemExit(f"set {SHODAN_KEY_ENV} in environment (.env)")

    api = shodan.Shodan(key)
    stats = {"domains": 0, "hosts": 0, "services": 0, "errors": 0}

    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, value FROM assets WHERE tenant_id = %s AND kind = 'domain'",
            (tenant_id,),
        )
        domains = cur.fetchall()

        for domain_id, domain in domains:
            try:
                resolved = api.dns.resolve(domain)
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                print(f"dns resolve failed for {domain}: {exc}")
                stats["errors"] += 1
                continue

            for ip in (resolved or {}).get("addresses", {}).values():
                _upsert_asset(cur, tenant_id, "ip", ip)
                stats["hosts"] += 1
                try:
                    host = api.host(ip)
                except Exception as exc:  # noqa: BLE001
                    print(f"host lookup failed for {ip}: {exc}")
                    stats["errors"] += 1
                    continue

                for svc in host.get("data", []):
                    product = (svc.get("product") or "").strip()
                    version = (svc.get("version") or "").strip()
                    vendor = product.lower().replace(" ", "-") or None
                    cpe = (f"cpe:2.3:a:{vendor}:{product.lower().replace(' ', '_')}:"
                           f"{version or '*'}") if vendor else None
                    _upsert_asset(
                        cur, tenant_id, "service",
                        f"{ip}:{svc.get('port')}",
                        ip=ip, port=svc.get("port"),
                        banner=(svc.get("banner") or "")[:2000] or None,
                        cpe=cpe,
                    )
                    stats["services"] += 1
            stats["domains"] += 1

        cur.execute(
            """
            INSERT INTO scan_jobs (tenant_id, kind, status, stats, started_at, finished_at)
            VALUES (%s, 'shodan_sync', 'done', %s, now(), now());
            """,
            (tenant_id, psycopg.Json(stats)),
        )
    return stats


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", type=int, required=True)
    args = ap.parse_args()
    print(f"shodan sync tenant {args.tenant}: {sync_tenant(args.tenant)}")
