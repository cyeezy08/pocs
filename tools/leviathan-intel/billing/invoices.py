"""Beta billing: manually-reconciled crypto invoices.

Why not an auto-settled PSP for the beta: Stripe is gone (account issue),
Telegram's custodial merchant rails (old Wallet Pay) carry the same
freeze/KYC class of risk we are escaping, and the 2026 TON Pay SDK is
Mini-App-first. The zero-dependency path: generate an invoice with a fixed
receive address + amount + memo, the operator confirms arrival (e.g. USDT
landing in their own wallet - a self-custodied or Telegram Wallet address,
their choice), and the API unlocks the tenant's plan atomically.

Supported rails (operator receives; customer picks):
    USDT-TON   -> PAY_ADDRESS_TON    (telegram-native, default)
    TON        -> PAY_ADDRESS_TON
    USDT-TRON  -> PAY_ADDRESS_TRON   (TRC-20, cheapest for SEA customers)
    USDT-SOL   -> PAY_ADDRESS_SOL    (SPL USDT)
    BTC        -> PAY_ADDRESS_BTC    (on-chain, higher fees)

Addresses are format-validated at invoice creation so a fat-fingered env
value can never silently swallow a customer's payment.

Plan ladder (USD/month, adjust as the product matures):
    trial -> starter -> pro
"""
from __future__ import annotations

import os
import re
import secrets
from datetime import datetime, timedelta, timezone

SUPPORTED_CURRENCIES = ("USDT-TON", "TON", "USDT-TRON", "USDT-SOL", "BTC")

# currency -> env var holding the receive address for that chain
CURRENCY_ADDRESS_ENV = {
    "USDT-TON": "PAY_ADDRESS_TON",
    "TON": "PAY_ADDRESS_TON",
    "USDT-TRON": "PAY_ADDRESS_TRON",
    "USDT-SOL": "PAY_ADDRESS_SOL",
    "BTC": "PAY_ADDRESS_BTC",
}
# legacy fallback: single PAY_ADDRESS serves the TON family if the specific
# var is unset (backwards compatible with the first billing deploy)
LEGACY_FALLBACK_ENV = "PAY_ADDRESS"
_FALLBACK_FOR = ("USDT-TON", "TON")

PLAN_PRICES_USD = {"trial": 0.0, "starter": 99.0, "pro": 299.0}
DEFAULT_INVOICE_DAYS = 3

MEMO_RE = re.compile(r"^LVTI-[0-9A-F]{6}$")

# --- address format validators (lightweight, no external deps) -------------

_BECH32_CHARSET = set("023456789acdefghjklmnpqrstuvwxyz")  # no 1, b, i, o
_BASE58_CHARSET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
                      "abcdefghijkmnopqrstuvwxyz")          # no 0, O, I, l
_TON_RE = re.compile(r"[UE][QD][A-Za-z0-9_-]{46}")          # user-friendly


def validate_address(currency: str, address: str) -> str:
    """Raise ValueError unless `address` is well-formed for `currency`'s chain."""
    addr = (address or "").strip()
    chain = {"USDT-TON": "ton", "TON": "ton", "USDT-TRON": "tron",
             "USDT-SOL": "sol", "BTC": "btc"}[validate_currency(currency)]

    if chain == "ton":
        ok = _TON_RE.fullmatch(addr) is not None
    elif chain == "btc":
        one_case = addr == addr.lower() or addr == addr.upper()
        low = addr.lower()
        ok = (one_case and low.startswith("bc1")
              and len(low) in (42, 62)
              and all(c in _BECH32_CHARSET for c in low[3:]))
    elif chain == "tron":
        ok = (addr.startswith("T") and len(addr) == 34
              and all(c in _BASE58_CHARSET for c in addr))
    else:  # sol
        ok = (32 <= len(addr) <= 44
              and all(c in _BASE58_CHARSET for c in addr))

    if not ok:
        raise ValueError(f"{currency} receive address failed {chain} "
                         f"format check - fix PAY_ADDRESS before invoicing")
    return addr


# --- invoices ---------------------------------------------------------------

def gen_memo() -> str:
    """Unique-on-invoice reference the customer includes with the transfer."""
    return f"LVTI-{secrets.token_hex(3).upper()}"


def validate_currency(currency: str) -> str:
    c = (currency or "").strip().upper()
    if c not in SUPPORTED_CURRENCIES:
        raise ValueError(
            f"unsupported currency {currency!r}; pick one of {', '.join(SUPPORTED_CURRENCIES)}"
        )
    return c


def resolve_address(currency: str) -> str:
    """Look up the operator's receive address for this rail. Raises
    RuntimeError when unconfigured (API maps that to 503)."""
    c = validate_currency(currency)
    env = CURRENCY_ADDRESS_ENV[c]
    addr = os.environ.get(env, "").strip()
    if not addr and c in _FALLBACK_FOR:
        addr = os.environ.get(LEGACY_FALLBACK_ENV, "").strip()
    if not addr:
        raise RuntimeError(
            f"{env} not configured - set the receive address for {c} in .env")
    return validate_address(c, addr)


def default_expiry(days: int = DEFAULT_INVOICE_DAYS) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def is_expired(expires_at: datetime | None, now: datetime | None = None) -> bool:
    if expires_at is None:
        return False
    now = now or datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return now >= expires_at


def pay_instructions(invoice: dict) -> dict:
    """Customer-facing payment card for one invoice row (dict)."""
    return {
        "invoice_id": invoice.get("id"),
        "memo": invoice.get("memo"),
        "pay_to": invoice.get("address"),
        "currency": invoice.get("currency"),
        "amount_usd": str(invoice.get("amount_usd")),
        "plan": invoice.get("plan"),
        "expires_at": str(invoice.get("expires_at")),
        "note": ("Send the equivalent in the listed currency and include the "
                 f"memo {invoice.get('memo')} in your transfer reference. "
                 "Access unlocks after confirmation."),
    }
