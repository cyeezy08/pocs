"""Offline tests for the Wallet Pay adapter (no network, no DB in CI)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from unittest.mock import patch

import pytest

from billing import wallet_pay as wp

# realistic fixtures shaped like the reference client's live samples
WEBHOOK_PAID = {
    "eventDateTime": "2026-09-11T06:00:00.000Z",
    "eventId": 10829789207553,
    "type": "ORDER_PAID",
    "payload": {
        "id": 10829787081217,
        "number": "E953D09Q",
        "externalId": "LVTI-INV-42",
        "orderAmount": {"currencyCode": "USD", "amount": "99.00"},
        "selectedPaymentOption": {"amount": {"currencyCode": "TON",
                                             "amount": "13.5"}},
        "orderCompletedDateTime": "2026-09-11T06:00:00.000Z",
    },
}
WEBHOOK_FAILED = {
    "eventId": 11044361216001,
    "eventDateTime": "2026-09-11T07:00:00.000Z",
    "payload": {
        "id": 11000119772673,
        "number": "LVDPW6K8",
        "status": "EXPIRED",
        "externalId": "LVTI-INV-43",
        "orderAmount": {"amount": "99.00", "currencyCode": "USD"},
        "orderCompletedDateTime": "2026-09-11T07:00:00.000Z",
    },
    "type": "ORDER_FAILED",
}


def test_compute_signature_matches_reference_algo():
    # independent re-implementation of the published scheme as the oracle
    key, ts, body = "tok", "1700000000", b'{"a":1}'
    expected = base64.b64encode(hmac.new(
        key.encode(),
        f"POST./webhooks/wallet-pay.{ts}.{base64.b64encode(body).decode()}".encode(),
        hashlib.sha256).digest()).decode()
    assert wp.compute_signature(key, "POST", "/webhooks/wallet-pay", ts,
                                body) == expected


def test_verify_webhook_accepts_and_rejects():
    body = json.dumps([WEBHOOK_PAID]).encode()
    sig = wp.compute_signature("tok", "POST", "/wh", "123", body)
    assert wp.verify_webhook("tok", "POST", "/wh", "123", sig, body)
    assert not wp.verify_webhook("tok", "POST", "/wh", "123", sig, body + b"x")
    assert not wp.verify_webhook("tok", "POST", "/wh", "124", sig, body)
    assert not wp.verify_webhook("tok", "POST", "/other", "123", sig, body)
    assert not wp.verify_webhook("tok", "POST", "/wh", "", sig, body)
    assert not wp.verify_webhook("tok", "POST", "/wh", "123", "", body)


def test_parse_webhook_extracts_fields():
    raw = json.dumps([WEBHOOK_PAID, WEBHOOK_FAILED]).encode()
    msgs = wp.parse_webhook(raw)
    assert len(msgs) == 2
    paid, failed = msgs
    assert paid["type"] == "ORDER_PAID"
    assert paid["external_id"] == "LVTI-INV-42"
    assert paid["wallet_order_id"] == 10829787081217
    assert paid["amount"] == "99.00"
    assert failed["status"] == "EXPIRED"
    assert failed["external_id"] == "LVTI-INV-43"


def test_parse_webhook_ignores_unknown_types_and_single_dicts():
    weird = {"eventId": 1, "type": "SOMETHING_NEW",
             "payload": {"externalId": "LVTI-INV-9"}}
    msgs = wp.parse_webhook(json.dumps([weird]).encode())
    assert msgs == []
    single = wp.parse_webhook(json.dumps(WEBHOOK_PAID).encode())
    assert len(single) == 1


def test_parse_webhook_rejects_garbage():
    with pytest.raises(ValueError):
        wp.parse_webhook(b"not json")
    with pytest.raises(ValueError):
        wp.parse_webhook(json.dumps([["nested"]]).encode())


def test_external_id_roundtrip():
    assert wp.invoice_id_from_external_id("LVTI-INV-42") == 42
    assert wp.invoice_id_from_external_id("LVTI-INV-0") == 0
    assert wp.invoice_id_from_external_id("LVTI-INV-abc") is None
    assert wp.invoice_id_from_external_id("uuid-thing") is None
    assert wp.invoice_id_from_external_id(None) is None
    assert wp.invoice_id_from_external_id("LVTI-INV-") is None


def _fake_response(payload: dict, status_code: int = 200):
    class R:
        def __init__(self):
            self.status_code = status_code
            self.text = json.dumps(payload)
        def raise_for_status(self):
            if self.status_code >= 400:
                raise AssertionError("raise_for_status on error")
        def json(self):
            return payload
    return R()


def test_create_order_body_shaping_and_response():
    client = wp.WalletPayClient("tok")
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured.update({"url": url, "json": json, "headers": headers})
        return _fake_response({
            "status": "SUCCESS",
            "data": {"id": "1082", "status": "ACTIVE",
                     "payLink": "https://t.me/wallet?start=abc",
                     "number": "E953D09Q"},
        })

    with patch("billing.wallet_pay.requests.post", side_effect=fake_post):
        out = client.create_order(
            amount=99, currency_code="USD", description="d",
            external_id="LVTI-INV-1", timeout_seconds=600,
            customer_telegram_user_id=777)

    assert captured["url"] == "https://pay.wallet.tg/wpay/store-api/v1/order"
    assert captured["headers"]["Wpay-Store-Api-Key"] == "tok"
    body = captured["json"]
    assert body["amount"] == {"amount": "99", "currencyCode": "USD"}
    assert body["externalId"] == "LVTI-INV-1"
    assert body["timeoutSeconds"] == 600
    assert body["customerTelegramUserId"] == 777
    assert out["pay_link"] == "https://t.me/wallet?start=abc"
    assert out["order_id"] == "1082"


def test_create_order_rejects_non_success_status():
    client = wp.WalletPayClient("tok")
    with patch("billing.wallet_pay.requests.post",
               return_value=_fake_response(
                   {"status": "INVALID_REQUEST", "message": "bad"}, 200)):
        with pytest.raises(wp.WalletPayError):
            client.create_order(amount=1, currency_code="USD",
                                description="d", external_id="x",
                                timeout_seconds=600)


def test_configuration_gate(monkeypatch):
    monkeypatch.delenv("WALLET_PAY_TOKEN", raising=False)
    assert wp.is_configured() is False
    with pytest.raises(RuntimeError):
        wp.client_from_env()
    monkeypatch.setenv("WALLET_PAY_TOKEN", "tok")
    assert wp.is_configured() is True
