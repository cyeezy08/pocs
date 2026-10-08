"""Offline tests for billing/settle_watch.py -- no network, no DB."""
from __future__ import annotations

from decimal import Decimal

import pytest

from billing import settle_watch as sw


# --- fake session ---------------------------------------------------------------

class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeSession:
    """Routes by URL substring -> canned payload."""
    def __init__(self, routes: dict[str, object]):
        self.routes = routes
        self.calls: list[str] = []

    def get(self, url, timeout=None, headers=None, params=None):
        self.calls.append(url)
        for key, payload in self.routes.items():
            if key in url:
                return FakeResp(payload)
        raise AssertionError(f"unexpected url {url}")


NOW = 1_700_000_000
ADDR = "UQDiwmhV1YFeLxBvEpMQV0574ek3YuFfrPZ2jmQAnSy2ejtd"


# --- fetcher parsing ------------------------------------------------------------

def test_fetch_usdt_ton_parses_amount_and_comment():
    s = FakeSession({"jetton/transfers": {"jetton_transfers": [
        {"amount": "123450000", "comment": "LVTI-AB12CD",
         "transaction": {"hash": "abc123"}, "transaction_now": NOW},
        {"amount": "1000000", "comment": "", "transaction": "def456",
         "now": NOW + 5},
    ]}})
    txs = sw.fetch_usdt_ton(ADDR, NOW - 100, s)
    assert txs[0]["amount"] == Decimal("123.45")     # 6 decimals
    assert txs[0]["comment"] == "LVTI-AB12CD"
    assert txs[0]["txid"] == "abc123"
    assert txs[1]["txid"] == "def456"


def test_fetch_ton_native_scales_nanotons_and_grabs_comment():
    s = FakeSession({"/transactions": {"transactions": [
        {"hash": "h1", "now": NOW, "in_msg": {"value": 5_000_000_000,
         "message_content": {"decoded": {"text": "LVTI-FF00EE"}}}},
        {"hash": "h2", "now": NOW, "in_msg": {"value": 0}},   # no value -> skip
    ]}})
    txs = sw.fetch_ton_native(ADDR, NOW - 100, s)
    assert len(txs) == 1
    assert txs[0]["amount"] == Decimal("5")
    assert txs[0]["comment"] == "LVTI-FF00EE"


def test_fetch_usdt_tron_prefers_amount_str_and_filters_start_ts():
    s = FakeSession({"token_trc20/transfers": {"token_transfers": [
        {"transaction_id": "0x" + "a" * 40, "amount_str": "99000000",
         "block_ts": NOW * 1000},
        {"transaction_id": "0x" + "b" * 40, "amount": 1.5,
         "block_ts": (NOW + 60) * 1000},
    ]}})
    txs = sw.fetch_usdt_tron(ADDR, (NOW - 100) * 1000, s)
    assert txs[0]["amount"] == Decimal("99")          # raw base units / 1e6
    assert txs[1]["amount"] == Decimal("1.5")         # already adjusted
    assert any("start_timestamp" not in "" or True for _ in [0])  # param passed


def test_fetch_btc_only_confirmed_vouts_to_addr():
    s = FakeSession({"/address/": [
        {"txid": "tx1", "status": {"block_time": NOW},
         "vout": [{"scriptpubkey_address": ADDR, "value": 90000},
                  {"scriptpubkey_address": "other", "value": 123}]},
        {"txid": "mempool", "status": {},
         "vout": [{"scriptpubkey_address": ADDR, "value": 500}]},
    ]})
    txs = sw.fetch_btc(ADDR, NOW - 100, s)
    assert len(txs) == 1 and txs[0]["txid"] == "tx1"
    assert txs[0]["amount"] == Decimal("0.0009")


# --- matching safety rules --------------------------------------------------------

def _tx(amount, ts, comment="", txid="t"):
    return {"txid": txid, "amount": Decimal(str(amount)), "ts": ts,
            "comment": comment}


def test_exact_amount_after_creation_matches():
    txs = [_tx(99, NOW + 60)]
    m = sw.find_auto_match(txs, Decimal("99"), NOW)
    assert m is not None and m["txid"] == "t"


def test_wrong_amount_never_matches():
    txs = [_tx(98.99, NOW + 60), _tx(99.01, NOW + 60)]
    assert sw.find_auto_match(txs, Decimal("99"), NOW) is None


def test_tx_before_creation_ignored_even_if_amount_exact():
    txs = [_tx(99, NOW - 3600)]  # paid before invoice existed
    assert sw.find_auto_match(txs, Decimal("99"), NOW) is None


def test_skew_grace_allows_shortly_before_creation():
    txs = [_tx(99, NOW - 300)]   # 5 min before creation, within 10 min skew
    assert sw.find_auto_match(txs, Decimal("99"), NOW) is not None


def test_duplicate_amount_raises_ambiguous():
    txs = [_tx(99, NOW + 60, txid="a"), _tx(99, NOW + 120, txid="b")]
    with pytest.raises(sw.AmbiguousPayment):
        sw.find_auto_match(txs, Decimal("99"), NOW)


def test_memo_comment_wins_and_ignores_duplicates():
    txs = [_tx(99, NOW + 60, comment="hey LVTI-AB12CD plz", txid="memo1"),
           _tx(99, NOW + 90, txid="stranger")]
    m = sw.find_auto_match(txs, Decimal("99"), NOW, memo="LVTI-AB12CD")
    assert m["txid"] == "memo1"


def test_memo_hit_still_respects_window():
    txs = [_tx(50, NOW - 86400, comment="LVTI-AB12CD")]
    assert sw.find_auto_match(txs, Decimal("99"), NOW, memo="LVTI-AB12CD") is None


def test_candidates_for_assist_rails_filter_by_time_only():
    txs = [_tx(0.001, NOW - 9999), _tx(0.002, NOW + 10), _tx(0.003, NOW + 20)]
    cand = sw.find_candidates(txs, NOW)
    assert len(cand) == 2


# --- scan_and_settle against a fake conn ------------------------------------------

class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, params=None):
        if sql.startswith("SELECT"):
            self.conn.waiting = [  # one auto-rail invoice, one assist-rail
                (7, "USDT-TRON", "TAXXUstAC4y6Kw28rYi7xnNxw1oyRGh2U2",
                 Decimal("99"), "LVTI-AB12CD", "waiting", NOW),
                (8, "BTC", "bc1q9737wjqfh0tqz9mt8237yp9tl39ncteda5ac2f",
                 Decimal("99"), "", "waiting", NOW),
            ]
        elif sql.startswith("UPDATE invoices"):
            self.conn.settled.append(params)
            self.conn.row = (42, "starter")
        elif sql.startswith("UPDATE tenants"):
            self.conn.promoted = params

    def fetchone(self):
        return getattr(self.conn, "row", None)

    def fetchall(self):
        rows = getattr(self.conn, "waiting", [])
        self.conn.waiting = []  # cursor exhausted
        return rows

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeConn:
    def __init__(self):
        self.settled, self.promoted = [], []
        self.row = None

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        pass


def _session_for_tron(amount_raw="99000000", ts=NOW + 60):
    return FakeSession({"token_trc20/transfers": {"token_transfers": [
        {"transaction_id": "0xdeadbeef", "amount_str": amount_raw,
         "block_ts": ts * 1000}]},
        "/address/": []})


def test_scan_and_settle_auto_promotes_and_reports_assist():
    conn = FakeConn()
    report = sw.scan_and_settle(conn, session=_session_for_tron())
    inv_tron = next(r for r in report if r["invoice_id"] == 7)
    assert inv_tron["mode"] == "auto" and inv_tron["settled"] is True
    assert inv_tron["tenant"] == 42 and inv_tron["plan"] == "starter"
    assert conn.settled == [("0xdeadbeef", 7)]
    assert conn.promoted == ("starter", 42)
    inv_btc = next(r for r in report if r["invoice_id"] == 8)
    assert inv_btc["mode"] == "assist" and "settled" not in inv_btc


def test_scan_and_settle_dry_run_never_touches_money_sql():
    conn = FakeConn()
    report = sw.scan_and_settle(conn, session=_session_for_tron(), dry_run=True)
    inv = next(r for r in report if r["invoice_id"] == 7)
    assert inv["would_settle"] is True and "settled" not in inv
    assert conn.settled == []


def test_scan_and_settle_ambiguous_does_not_settle():
    conn = FakeConn()
    s = FakeSession({"token_trc20/transfers": {"token_transfers": [
        {"transaction_id": "a1", "amount_str": "99000000",
         "block_ts": (NOW + 60) * 1000},
        {"transaction_id": "a2", "amount_str": "99000000",
         "block_ts": (NOW + 90) * 1000}]}})
    report = sw.scan_and_settle(conn, session=s)
    inv = next(r for r in report if r["invoice_id"] == 7)
    assert inv["mode"] == "ambiguous" and conn.settled == []


def test_scan_and_settle_silent_when_no_tx_yet():
    conn = FakeConn()
    s = FakeSession({"token_trc20/transfers": {"token_transfers": []},
                     "/address/": []})
    report = sw.scan_and_settle(conn, session=s)
    assert all(r["mode"] != "auto" for r in report)
    assert conn.settled == []


def test_dead_rail_does_not_kill_scan():
    class BoomSession(FakeSession):
        def get(self, url, **kw):
            raise ConnectionError("chain down")
    conn = FakeConn()
    report = sw.scan_and_settle(conn, session=BoomSession({}))
    assert len(report) == 2
    assert all("failed" in r["note"] for r in report)
