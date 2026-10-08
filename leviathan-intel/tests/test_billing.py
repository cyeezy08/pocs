"""Offline tests for beta billing helpers (no network, no DB in CI)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest

from billing import invoices as bi


def test_memo_format():
    for _ in range(50):
        assert bi.MEMO_RE.fullmatch(bi.gen_memo())


def test_memo_uniqueness_reasonable():
    memos = {bi.gen_memo() for _ in range(500)}
    assert len(memos) > 490  # 24-bit space; collisions should be rare


def test_currency_validation():
    assert bi.validate_currency("usdt-ton") == "USDT-TON"
    assert bi.validate_currency("TON") == "TON"
    assert bi.validate_currency("usdt-tron") == "USDT-TRON"
    assert bi.validate_currency("usdt-sol") == "USDT-SOL"
    assert bi.validate_currency("btc") == "BTC"
    with pytest.raises(ValueError):
        bi.validate_currency("PAYPAL")
    with pytest.raises(ValueError):
        bi.validate_currency("ETH")
    with pytest.raises(ValueError):
        bi.validate_currency("")


# --- address format validators ----------------------------------------------

BTC_OK = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"   # BIP173 test vector
TON_OK = "UQ" + "A" * 46
SOL_OK = "C" + "z" * 43
TRX_OK = "T" + "x" * 33


def test_valid_addresses_accepted():
    assert bi.validate_address("BTC", BTC_OK) == BTC_OK
    assert bi.validate_address("ton", TON_OK)
    assert bi.validate_address("USDT-SOL", SOL_OK)
    assert bi.validate_address("USDT-TRON", TRX_OK)


def test_invalid_addresses_rejected():
    with pytest.raises(ValueError):
        bi.validate_address("BTC", "0x9737wjqfh0tqz9mt8237yp9tl39ncteda5ac2f")
    with pytest.raises(ValueError):
        bi.validate_address("BTC", "bc1qZI9")            # too short + bad charset
    with pytest.raises(ValueError):
        bi.validate_address("TON", "UQshort")             # wrong length
    with pytest.raises(ValueError):
        bi.validate_address("USDT-TRON", "0x" + "a" * 40)  # ETH-looking
    with pytest.raises(ValueError):
        bi.validate_address("USDT-SOL", "l0O!" + "z" * 40)  # non-base58
    with pytest.raises(ValueError):
        bi.validate_address("USDT-TON", "")


def test_resolver_maps_currencies_to_env(monkeypatch):
    monkeypatch.setenv("PAY_ADDRESS_TON", TON_OK)
    monkeypatch.setenv("PAY_ADDRESS_TRON", TRX_OK)
    monkeypatch.setenv("PAY_ADDRESS_SOL", SOL_OK)
    monkeypatch.setenv("PAY_ADDRESS_BTC", BTC_OK)
    assert bi.resolve_address("USDT-TON") == TON_OK
    assert bi.resolve_address("TON") == TON_OK
    assert bi.resolve_address("USDT-TRON") == TRX_OK
    assert bi.resolve_address("USDT-SOL") == SOL_OK
    assert bi.resolve_address("BTC") == BTC_OK


def test_resolver_legacy_fallback_for_ton_family(monkeypatch):
    monkeypatch.delenv("PAY_ADDRESS_TON", raising=False)
    monkeypatch.setenv("PAY_ADDRESS", TON_OK)
    assert bi.resolve_address("USDT-TON") == TON_OK
    with pytest.raises(RuntimeError):
        bi.resolve_address("BTC")  # no legacy fallback outside TON family


def test_resolver_rejects_malformed_configured_address(monkeypatch):
    monkeypatch.setenv("PAY_ADDRESS_BTC", "bc1qNOT_VALID")
    with pytest.raises(ValueError):
        bi.resolve_address("BTC")


def test_unconfigured_rail_raises_runtime_error(monkeypatch, ):
    for var in ("PAY_ADDRESS_TON", "PAY_ADDRESS", "PAY_ADDRESS_TRON",
                "PAY_ADDRESS_SOL", "PAY_ADDRESS_BTC"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(RuntimeError):
        bi.resolve_address("USDT-TRON")


# --- invoices ----------------------------------------------------------------

def test_expiry_default_is_three_days():
    before = datetime.now(timezone.utc)
    exp = bi.default_expiry()
    after = datetime.now(timezone.utc)
    assert before + timedelta(days=3) <= exp <= after + timedelta(days=3)


def test_is_expired_states():
    now = datetime.now(timezone.utc)
    assert bi.is_expired(now - timedelta(minutes=1), now=now)
    assert not bi.is_expired(now + timedelta(days=1), now=now)
    assert not bi.is_expired(None, now=now)
    naive = datetime.now() + timedelta(days=1)
    assert not bi.is_expired(naive, now=now)  # naive datetime treated as UTC


def test_pay_instructions_shape():
    inv = {
        "id": 7, "memo": "LVTI-ABC123", "address": TON_OK,
        "currency": "USDT-TON", "amount_usd": 99, "plan": "starter",
        "expires_at": datetime.now(timezone.utc),
    }
    card = bi.pay_instructions(inv)
    assert card["pay_to"] == TON_OK
    assert card["memo"] == "LVTI-ABC123"
    assert card["amount_usd"] == "99"
    assert "confirmation" in card["note"].lower()


def test_plan_prices_cover_api_plan_values():
    api_plans = {"trial", "starter", "pro"}
    assert set(bi.PLAN_PRICES_USD) == api_plans
    assert bi.PLAN_PRICES_USD["pro"] > bi.PLAN_PRICES_USD["starter"] > 0


def test_memo_regex_anchors():
    assert re.match(r"\^", bi.MEMO_RE.pattern)  # anchored, no partial matches
