"""Discord webhook alerting: push critical/high findings to an operator or
tenant channel. The "see shit work" surface -- no dashboard needed, your own
Discord lights up when a tenant's asset catches a KEV'd CVE.

Config: DISCORD_WEBHOOK_URL env (channel webhook from
Discord -> channel settings -> integrations). Unset = alerts disabled, never
an error (the pipeline must run without Discord).

Design notes:
    * one message per scan pass, findings batched into a single embed
      (Discord hard-caps: 10 embeds/msg, ~6000 chars total; we cap fields)
    * severity color: critical red, high orange; KEV badge in the title line
      because that's the "drop everything" signal
    * alert-worthy = status 'open' AND priority >= threshold (default 60:
      critical + high bands). Remediated/triaged findings don't re-ping.
    * send() failures raise -- the caller decides whether alerts are fatal
      (pipeline) or best-effort (CLI prints and continues).

CLI:
    python -m alerting.discord --tenant 2                # one tenant's alerts
    python -m alerting.discord                           # all tenants
    python -m alerting.discord --dry-run                 # print, don't send
    python -m alerting.discord --test                    # "it's alive" ping
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import requests

WEBHOOK_ENV = "DISCORD_WEBHOOK_URL"
DEFAULT_MIN_PRIORITY = 60          # critical (>=80) + high (>=60)
MAX_FIELDS = 10                    # Discord embed cap; keep headroom for text

COLORS = {"critical": 0xE74C3C, "high": 0xE67E22,
          "medium": 0xF1C40F, "low": 0x95A5A6}

_QUERY = (
    "SELECT f.id, f.priority, f.reasons, c.cve_id, c.cvss, c.kev, "
    "       a.value AS asset, a.kind AS asset_kind, t.name AS tenant, "
    "       c.remediation "
    "FROM findings f "
    "JOIN cves c   ON c.cve_id = f.cve_id "
    "JOIN assets a ON a.id = f.asset_id "
    "JOIN tenants t ON t.id = a.tenant_id "
    "WHERE f.status = 'open' AND f.priority >= %s "
    "  AND (%s::int IS NULL OR t.id = %s) "
    "ORDER BY f.priority DESC, c.kev DESC "
    "LIMIT %s"
)


def fetch_alertable(conn, tenant_id: int | None = None,
                    min_priority: int = DEFAULT_MIN_PRIORITY,
                    limit: int = MAX_FIELDS) -> list[dict]:
    """Open findings above the threshold, worst first."""
    with conn.cursor() as cur:
        cur.execute(_QUERY, (min_priority, tenant_id, tenant_id, limit))
        cols = [d.name for d in cur.description] if cur.description else []
        rows = cur.fetchall()
    return [dict(zip(cols, r)) for r in rows]


def _badge(kev: bool, reasons: list | str) -> str:
    tags = []
    if kev:
        tags.append("KEV")
    text = (json.dumps(reasons) if not isinstance(reasons, str)
            else reasons).lower()
    if "poc" in text:
        tags.append("PoC")
    return (" [" + " | ".join(tags) + "]") if tags else ""


def build_payload(findings: list[dict], title: str | None = None) -> dict[str, Any]:
    """One Discord message: an embed listing findings worst-first."""
    if not findings:
        return {}
    top = int(findings[0]["priority"])
    band = ("critical" if top >= 80 else "high" if top >= 60
            else "medium" if top >= 35 else "low")
    fields = []
    for f in findings[:MAX_FIELDS]:
        name = (f"[{f['priority']:>3}] {f['cve_id']}"
                f"{_badge(bool(f.get('kev')), f.get('reasons') or [])}"
                f" - {f['asset']}")
        remediation = (f.get("remediation") or "").strip()
        fix = ("Fix: " + remediation[:180]) if remediation else "Fix: see advisory"
        fields.append({"name": name[:250], "value": fix[:1000], "inline": False})
    return {
        "username": "Leviathan Intel",
        "embeds": [{
            "title": title or f"🚨 {len(findings)} alertable finding(s)",
            "color": COLORS[band],
            "fields": fields,
            "footer": {"text": f"open findings >= {DEFAULT_MIN_PRIORITY} "
                               "priority - triage in the API"},
        }],
    }


def send(session: requests.Session, webhook_url: str,
         payload: dict[str, Any]) -> None:
    r = session.post(webhook_url, json=payload, timeout=15,
                     headers={"User-Agent": "leviathan-intel-alerts/0.1"})
    r.raise_for_status()


def alert(conn, session: requests.Session | None = None,
          tenant_id: int | None = None,
          min_priority: int = DEFAULT_MIN_PRIORITY,
          dry_run: bool = False) -> dict:
    """Fetch -> build -> send. Returns a summary for the caller/CLI."""
    webhook = os.environ.get(WEBHOOK_ENV, "").strip()
    findings = fetch_alertable(conn, tenant_id, min_priority)
    summary: dict[str, Any] = {"alertable": len(findings), "sent": False,
                               "reason": ""}
    if not findings:
        summary["reason"] = "nothing above threshold"
        return summary
    payload = build_payload(findings)
    if dry_run:
        summary["reason"] = "dry-run"
        summary["payload"] = payload
        return summary
    if not webhook:
        summary["reason"] = (f"{WEBHOOK_ENV} unset - alerts disabled "
                             "(not an error)")
        return summary
    send(session or requests.Session(), webhook, payload)
    summary["sent"] = True
    return summary


# --- CLI ---------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Discord alert push for findings")
    ap.add_argument("--tenant", type=int, help="limit to one tenant id")
    ap.add_argument("--min-priority", type=int, default=DEFAULT_MIN_PRIORITY)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the payload, never POST")
    ap.add_argument("--test", action="store_true",
                    help="send a one-line wiring check (needs webhook env)")
    args = ap.parse_args(argv)

    if args.test:
        webhook = os.environ.get(WEBHOOK_ENV, "").strip()
        if not webhook:
            print(f"{WEBHOOK_ENV} unset - set it first")
            return 1
        send(requests.Session(), webhook, {
            "username": "Leviathan Intel",
            "content": ("✅ alert wiring live - critical/high findings "
                        "will land here"),
        })
        print("test ping sent")
        return 0

    import psycopg  # DB modes only
    dsn = os.environ.get("DATABASE_URL",
                         "postgresql://leviathan@localhost/leviathan")
    with psycopg.connect(dsn) as conn:
        result = alert(conn, tenant_id=args.tenant,
                       min_priority=args.min_priority, dry_run=args.dry_run)
    print(json.dumps({k: v for k, v in result.items() if k != "payload"},
                     indent=2))
    if args.dry_run and result.get("payload"):
        print(json.dumps(result["payload"], indent=2)[:2000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
