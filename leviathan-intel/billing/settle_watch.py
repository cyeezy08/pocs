"""Keyless auto-settle watcher: poll public chain APIs, promote paid invoices.

Fastest no-KYB path to hands-off billing. No third-party merchant account,
no API keys -- the watcher reads the same public ledgers customers pay into:

    USDT-TON   toncenter.com  /jetton/transfers?owner=&jetton_address=   (FULL AUTO)
    USDT-TRON  tronscanapi.com /token_trc20/transfers?to_address=         (FULL AUTO)
    TON        toncenter.com  /transactions?to=                          (assist)
    BTC        blockstream.info /address/{a}/txs                         (assist)
    USDT-SOL   manual for v1 (SPL ATA watch needs derived token accounts)

FULL AUTO rails are stablecoin-pegged: the invoice's amount_usd IS the USDT
amount, so an exact-amount match after the invoice's creation timestamp is
deterministic (no FX drift, unlike TON-native/BTC). TON native transfers that
carry the invoice memo (LVTI-XXXXXX comment) also settle deterministically.

Safety rules (beta volume assumptions, revisit at scale):
    * tx must arrive AFTER the invoice was created (10 min clock skew grace)
    * amount must equal expected exactly
    * two or more candidate txs with the same amount in the window -> mark
      the invoice 'ambiguous' in the summary and DO NOT auto-settle (an
      operator resolves it; duplicates are vanishingly rare at beta volume)
    * settle reuses the same guarded SQL as the API endpoint, so an invoice
      already paid/expired/cancelled can never double-promote a tenant

Usage:
    python -m billing.settle_watch --probe              # demo, no DB
    python -m billing.settle_watch --once               # one scan, needs DB
    python -m billing.settle_watch --loop 60            # poll every 60s
    python -m billing.settle_watch --once --dry-run     # report, don't settle
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from decimal import Decimal
from typing import Any

import requests

# --- rails -------------------------------------------------------------------

USDT_TON_MASTER = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"  # TON USDT jetton
USDT_TRON_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"             # TRC-20 USDT
TONCENTER = "https://toncenter.com/api/v3"
TRONSCAN = "https://apilist.tronscanapi.com"
BLOCKSTREAM = "https://blockstream.info/api"

AUTO_RAILS = ("USDT-TON", "USDT-TRON")          # stablecoin-exact: auto-settle
ASSIST_RAILS = ("TON", "BTC")                   # report candidates only
SKEW_SECS = 600                                  # clock-skew grace window
HTTP_TIMEOUT = 15
UA = {"User-Agent": "leviathan-intel-settle-watch/0.1"}

MEMO_PREFIX = "LVTI-"


class AmbiguousPayment(Exception):
    """Two+ indistinguishable candidates landed in the window -- operator call."""


# --- fetchers (all return [{txid, amount, ts, comment?, out?}]) ---------------

def _get(session: requests.Session, url: str, **kw) -> list | dict:
    r = session.get(url, timeout=HTTP_TIMEOUT, headers=UA, **kw)
    r.raise_for_status()
    return r.json()


def fetch_usdt_ton(addr: str, since_ts: int, session: requests.Session) -> list[dict]:
    """Inbound USDT jetton transfers to `addr` (owner) since `since_ts`."""
    data = _get(session, f"{TONCENTER}/jetton/transfers",
                params={"owner": addr, "jetton_address": USDT_TON_MASTER,
                        "limit": 100})
    out = []
    for j in data.get("jetton_transfers", []):
        # toncenter filters to our owner server-side; nothing else to check
        ts = int(j.get("transaction_now") or j.get("now") or 0)
        comment = (j.get("comment") or "").strip()
        tx = j.get("transaction")
        txid = tx.get("hash", "") if isinstance(tx, dict) else str(tx or "")
        out.append({"txid": txid,
                    "amount": Decimal(str(j.get("amount", "0"))) / Decimal(10**6),
                    "ts": ts, "comment": comment})
    return out


def fetch_ton_native(addr: str, since_ts: int, session: requests.Session) -> list[dict]:
    """Inbound native TON transfers (value in nanotons -> TON)."""
    data = _get(session, f"{TONCENTER}/transactions",
                params={"to": addr, "limit": 100})
    out = []
    for t in data.get("transactions", []):
        msg = t.get("in_msg") or {}
        value = msg.get("value")
        if not value:
            continue
        # comment may surface under several toncenter shapes; be forgiving
        content = (msg.get("message_content") or {})
        decoded = (content.get("decoded") or {}) if isinstance(content, dict) else {}
        comment = (decoded.get("text") or decoded.get("comment")
                   or msg.get("comment") or msg.get("message") or "").strip()
        out.append({"txid": str(t.get("hash", "")),
                    "amount": Decimal(str(value)) / Decimal(10**9),
                    "ts": int(t.get("now") or 0),
                    "comment": comment})
    return out


def fetch_usdt_tron(addr: str, since_ms: int, session: requests.Session) -> list[dict]:
    """Inbound TRC-20 USDT transfers to `addr` since `since_ms` (epoch ms)."""
    data = _get(session, f"{TRONSCAN}/api/token_trc20/transfers",
                params={"to_address": addr, "contract_address": USDT_TRON_CONTRACT,
                        "limit": 100, "start_timestamp": since_ms})
    out = []
    for t in data.get("token_transfers", []):
        # tronscan: amount_str = raw base units (6 dp); amount = adjusted float
        if t.get("amount_str"):
            amount = Decimal(str(t["amount_str"])) / Decimal(10**6)
        else:
            amount = Decimal(str(t.get("amount") or "0"))
        out.append({"txid": str(t.get("transaction_id", "")),
                    "amount": amount,
                    "ts": int(t.get("block_ts", 0)) // 1000,
                    "comment": (t.get("memo") or "").strip()})
    return out


def fetch_btc(addr: str, since_ts: int, session: requests.Session) -> list[dict]:
    """Confirmed BTC UTXOs paid to `addr` (sats) -- assist mode only."""
    data = _get(session, f"{BLOCKSTREAM}/address/{addr}/txs")
    out = []
    for t in data:
        block_time = int(((t.get("status") or {}).get("block_time")) or 0)
        if not block_time:
            continue  # unconfirmed
        for vout in t.get("vout", []):
            if vout.get("scriptpubkey_address") == addr:
                out.append({"txid": str(t.get("txid", "")),
                            "amount": Decimal(str(vout.get("value", 0))) / Decimal(10**8),
                            "ts": block_time, "comment": "", "unit": "BTC"})
    return out


FETCHERS = {
    "USDT-TON": fetch_usdt_ton,
    "TON": fetch_ton_native,
    "USDT-TRON": fetch_usdt_tron,
    "BTC": fetch_btc,
}


# --- matching ------------------------------------------------------------------

def _memo_hit(tx: dict, memo: str) -> bool:
    return bool(memo) and memo.upper() in (tx.get("comment") or "").upper()


def find_auto_match(txs: list[dict], expected: Decimal, created_ts: int,
                    memo: str = "") -> dict | None:
    """Deterministic pick for auto-settle. Priority:
    1. a tx whose comment contains the invoice memo (unambiguous by design)
    2. exact-amount tx that arrived after invoice creation (stablecoin rails)
    Raises AmbiguousPayment when rule 2 has 2+ candidates (never auto-settles).
    """
    if memo:
        hits = [t for t in txs if _memo_hit(t, memo) and t["ts"] >= created_ts - SKEW_SECS]
        if len(hits) == 1:
            return hits[0]
    cand = [t for t in txs
            if t["amount"] == expected and t["ts"] >= created_ts - SKEW_SECS]
    if len(cand) > 1:
        raise AmbiguousPayment(f"{len(cand)} identical-amount txs in window")
    return cand[0] if cand else None


def find_candidates(txs: list[dict], created_ts: int) -> list[dict]:
    """Assist rails (TON/BTC): inbound txs after creation -- operator eyeballs
    (amount is quoted in USD, rail unit drifts, so no exact-match auto)."""
    return [t for t in txs if t["ts"] >= created_ts - SKEW_SECS]


# --- settle (same guarded SQL as POST /billing/invoices/{id}/paid) -------------

_SETTLE_SQL = (
    "UPDATE invoices SET status = 'paid', paid_at = now(), tx_ref = %s "
    "WHERE id = %s AND status = 'waiting' AND expires_at > now() "
    "RETURNING tenant_id, plan"
)
_PROMOTE_SQL = "UPDATE tenants SET plan = %s WHERE id = %s"


def settle(conn, invoice_id: int, tx_ref: str) -> tuple[int, str] | None:
    """Atomically mark paid + promote. Returns (tenant_id, plan) or None."""
    with conn.cursor() as cur:
        cur.execute(_SETTLE_SQL, (tx_ref, invoice_id))
        row = cur.fetchone()
        if not row:
            return None  # already paid / expired / cancelled elsewhere
        tenant_id, plan = row
        cur.execute(_PROMOTE_SQL, (plan, tenant_id))
    conn.commit()
    return tenant_id, plan


def scan_and_settle(conn, session: requests.Session | None = None,
                    dry_run: bool = False) -> list[dict]:
    """One pass: every waiting invoice -> poll its rail -> settle on match."""
    session = session or requests.Session()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, currency, address, amount_usd, memo, status, "
            "       EXTRACT(epoch FROM created_at)::bigint "
            "FROM invoices WHERE status = 'waiting' AND expires_at > now()")
        rows = cur.fetchall()
    report = []
    for (inv_id, currency, address, amount_usd, memo, _status, created_ts) in rows:
        entry: dict[str, Any] = {"invoice_id": inv_id, "currency": currency,
                                 "mode": "manual"}
        fetch = FETCHERS.get(currency)
        if not fetch:
            entry["note"] = "no watcher for rail (USDT-SOL: manual for v1)"
            report.append(entry)
            continue
        since = int(created_ts) - SKEW_SECS
        try:
            txs = fetch(address, since, session)
            if currency in AUTO_RAILS:
                expected = Decimal(str(amount_usd))  # USDT peg: usd == units
                match = find_auto_match(txs, expected, int(created_ts), memo)
                if match:
                    entry.update(mode="auto", txid=match["txid"],
                                 amount=str(match["amount"]))
                    if not dry_run:
                        res = settle(conn, inv_id, match["txid"][:100])
                        entry["settled"] = bool(res)
                        if res:
                            entry["tenant"], entry["plan"] = res
                    else:
                        entry["would_settle"] = True
                else:
                    entry["note"] = "no qualifying tx yet"
            else:
                cand = find_candidates(txs, int(created_ts))
                entry.update(mode="assist",
                             candidates=len(cand),
                             note="operator confirms (non-pegged rail)")
                if cand:
                    entry["latest"] = {"txid": cand[-1]["txid"][:32],
                                       "amount": str(cand[-1]["amount"]),
                                       "ts": cand[-1]["ts"]}
        except AmbiguousPayment as e:
            entry.update(mode="ambiguous", note=str(e))
        except Exception as e:  # one dead rail must not kill the scan
            entry["note"] = f"rail fetch failed: {type(e).__name__}"
        report.append(entry)
    return report


# --- CLI -----------------------------------------------------------------------

def _demo_env() -> dict[str, str]:
    """Pull PAY_ADDRESS_* from the local .env for --probe (no DB needed)."""
    env = dict(os.environ)
    for path in ("/home/z/my-project/.env", ".env"):
        if os.path.exists(path):
            for line in open(path):
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env.setdefault(k.strip(), v.strip())
            break
    return env


def probe(session: requests.Session) -> None:
    """Demo: live-poll all rails for the operator's addresses, print state."""
    env = _demo_env()
    rails = [("USDT-TON", "PAY_ADDRESS_TON"), ("TON", "PAY_ADDRESS_TON"),
             ("USDT-TRON", "PAY_ADDRESS_TRON"), ("BTC", "PAY_ADDRESS_BTC")]
    print("settle_watch probe -- live chain state (no DB touched)\n")
    for currency, env_key in rails:
        addr = env.get(env_key, "").strip()
        if not addr:
            print(f"  {currency:<10} {env_key} unset, skip")
            continue
        since = int(time.time()) - 90 * 86400  # 90d lookback for the demo
        try:
            txs = FETCHERS[currency](addr, since, session)
            print(f"  {currency:<10} {addr[:10]}...{addr[-6:]}  "
                  f"inbound(90d): {len(txs)}")
            for t in txs[-3:]:
                print(f"      {t['ts']}  {t['amount']}  "
                      f"txid={t['txid'][:24]}  memo={t.get('comment', '')!r}")
            if not txs:
                print("      (nothing yet -- watcher is armed and listening)")
        except Exception as e:
            print(f"  {currency:<10} fetch failed: {type(e).__name__}: {e}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="keyless invoice settle watcher")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--once", action="store_true", help="one scan (needs DB)")
    g.add_argument("--loop", type=int, metavar="SECS",
                   help="poll forever every SECS (needs DB)")
    g.add_argument("--probe", action="store_true", help="demo, no DB")
    ap.add_argument("--dry-run", action="store_true",
                    help="scan + report, never settle")
    args = ap.parse_args(argv)

    if args.probe:
        probe(requests.Session())
        return 0
    if not (args.once or args.loop):
        ap.error("pick --probe, --once or --loop")

    import psycopg  # deferred: only the DB modes need it
    dsn = os.environ.get("DATABASE_URL", "postgresql://leviathan@localhost/leviathan")
    interval = max(30, args.loop or 60)
    while True:
        with psycopg.connect(dsn) as conn:
            rows = scan_and_settle(conn, dry_run=args.dry_run)
        for r in rows:
            flag = {"auto": "AUTO", "assist": "CAND", "ambiguous": "!!"}[r["mode"]]
            print(f"[{time.strftime('%H:%M:%S')}] {flag:<4} "
                  f"inv={r['invoice_id']} {r['currency']:<10} "
                  f"{r.get('note') or (r.get('txid', '')[:24] + (' -> paid' if r.get('settled') else ''))}")
        if not args.loop:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
