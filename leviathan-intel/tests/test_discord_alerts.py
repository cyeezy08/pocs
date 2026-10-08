"""Offline tests for alerting/discord.py -- no network, no DB."""
from __future__ import annotations

import json

import pytest

from alerting import discord as da


# --- fakes ---------------------------------------------------------------------

class FakeResp:
    def __init__(self, status=204):
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, status=204):
        self.status = status
        self.posts: list[dict] = []

    def post(self, url, json=None, timeout=None, headers=None):
        self.posts.append({"url": url, "json": json})
        return FakeResp(self.status)


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, params=None):
        cols = ["id", "priority", "reasons", "cve_id", "cvss", "kev",
                "asset", "asset_kind", "tenant", "remediation"]
        self.description = [type("D", (), {"name": c})() for c in cols]
        self.rows = [tuple(r[c] for c in cols) for r in self.conn.rows]

    def fetchall(self):
        return self.rows

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeConn:
    def __init__(self, rows):
        self.rows = rows

    def cursor(self):
        return FakeCursor(self)


def _f(prio=95, cve="CVE-2026-1234", asset="acme.com", kev=True,
       reasons=None, remediation="Patch to v2.3.1", fid=1):
    return {"id": fid, "priority": prio, "reasons": reasons or [], "cve_id": cve,
            "cvss": 9.8, "kev": kev, "asset": asset, "asset_kind": "domain",
            "tenant": "acme", "remediation": remediation}


# --- query ---------------------------------------------------------------------

def test_fetch_alertable_binds_tenant_threshold_limit():
    seen = {}

    class SpyCursor(FakeCursor):
        def execute(self, sql, params):
            seen["sql"] = sql
            seen["params"] = params
            super().execute(sql, params)

    conn = FakeConn([])
    conn.cursor = lambda: SpyCursor(conn)
    da.fetch_alertable(conn, tenant_id=7, min_priority=80, limit=5)
    assert seen["params"] == (80, 7, 7, 5)
    assert "JOIN tenants" in seen["sql"] and "status = 'open'" in seen["sql"]


# --- payload building ------------------------------------------------------------

def test_payload_critical_red_with_kev_badge():
    p = da.build_payload([_f(prio=95, kev=True,
                             reasons=["In CISA KEV -> +15"])])

    embed = p["embeds"][0]
    assert embed["color"] == da.COLORS["critical"]
    assert "[KEV" in embed["fields"][0]["name"]
    assert "CVE-2026-1234" in embed["fields"][0]["name"]
    assert "acme.com" in embed["fields"][0]["name"]


def test_payload_poc_badge_from_reasons_text():
    p = da.build_payload([_f(prio=65, kev=False,
                             reasons=["Public PoC available -> +5"])])
    assert "PoC" in p["embeds"][0]["fields"][0]["name"]
    assert p["embeds"][0]["color"] == da.COLORS["high"]


def test_payload_caps_at_ten_fields():
    rows = [_f(fid=i, prio=70 - (i % 10)) for i in range(15)]
    p = da.build_payload(rows)
    assert len(p["embeds"][0]["fields"]) == 10


def test_payload_includes_remediation():
    p = da.build_payload([_f(remediation="Upgrade openssl to 3.2")])
    assert "Upgrade openssl to 3.2" in p["embeds"][0]["fields"][0]["value"]


def test_payload_empty_when_no_findings():
    assert da.build_payload([]) == {}


# --- alert() flow ------------------------------------------------------------------

def test_alert_no_webhook_is_not_an_error(monkeypatch):
    monkeypatch.delenv(da.WEBHOOK_ENV, raising=False)
    conn = FakeConn([_f()])
    s = FakeSession()
    r = da.alert(conn, session=s)
    assert r["sent"] is False and "unset" in r["reason"]
    assert s.posts == []                      # nothing went anywhere


def test_alert_sends_batched_embed(monkeypatch):
    monkeypatch.setenv(da.WEBHOOK_ENV, "https://discord.com/api/webhooks/x/y")
    conn = FakeConn([_f(fid=1, prio=95), _f(fid=2, prio=62,
                                            cve="CVE-2026-9999", kev=False)])
    s = FakeSession()
    r = da.alert(conn, session=s)
    assert r["sent"] is True
    assert len(s.posts) == 1
    sent = s.posts[0]["json"]["embeds"][0]
    assert len(sent["fields"]) == 2           # batched, one message


def test_alert_no_findings_short_circuits(monkeypatch):
    monkeypatch.setenv(da.WEBHOOK_ENV, "https://discord.com/api/webhooks/x/y")
    s = FakeSession()
    r = da.alert(FakeConn([]), session=s)
    assert r["alertable"] == 0 and s.posts == []


def test_alert_dry_run_builds_but_never_posts(monkeypatch):
    monkeypatch.setenv(da.WEBHOOK_ENV, "https://discord.com/api/webhooks/x/y")
    s = FakeSession()
    r = da.alert(FakeConn([_f()]), session=s, dry_run=True)
    assert r["reason"] == "dry-run" and "payload" in r
    assert s.posts == []


def test_alert_http_failure_raises(monkeypatch):
    monkeypatch.setenv(da.WEBHOOK_ENV, "https://discord.com/api/webhooks/x/y")
    with pytest.raises(RuntimeError):
        da.alert(FakeConn([_f()]), session=FakeSession(status=500))


# --- misc ---------------------------------------------------------------------

def test_badge_handles_weird_reasons_shapes():
    assert "KEV" in da._badge(True, None)
    assert da._badge(False, "no tags here") == ""
    assert "PoC" in da._badge(False, {"weird": ["public PoC available"]})
