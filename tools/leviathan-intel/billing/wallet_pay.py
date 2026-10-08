"""Telegram Wallet Pay integration - optional auto-settle path.

Manual crypto invoices (see invoices.py) are the beta default because they
have zero third-party dependency. Wallet Pay is the *upgrade*: the customer
gets a 👛 Wallet Pay checkout link, pays from their Telegram balance
(TON/BTC/USDT), and our webhook settles the invoice automatically.

Verified against the live API + reference client (Olegt0rr/TelegramWalletPay,
2026-09):
  - auth header:            Wpay-Store-Api-Key: <store token>
  - create order:           POST {host}/wpay/store-api/v1/order
                            -> {"status": "SUCCESS", "data": {"id": str,
                               "payLink": str, ...}}
  - webhook:                body = LIST of messages
                            {"eventDateTime", "eventId",
                             "type": "ORDER_PAID" | "ORDER_FAILED",
                             "payload": {"id", "number", "externalId",
                                         "status", "orderAmount", ...}}
  - webhook auth:           headers WalletPay-Timestamp + WalletPay-Signature;
                            signature = base64(HMAC-SHA256(store_token,
                              "{METHOD}.{path}.{timestamp}.{base64(body)}"))

Gate: WALLET_PAY_TOKEN env unset -> endpoints report 503 and the manual
invoice flow keeps working. Requires Wallet Pay merchant approval (KYB) at
https://pay.wallet.tg/ before a token exists.

external_id convention: "LVTI-INV-{invoice_id}" - links Wallet orders back
to our invoices table without trusting customer-supplied data.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from secrets import compare_digest

import requests

DEFAULT_API_HOST = "https://pay.wallet.tg"
AUTH_HEADER = "Wpay-Store-Api-Key"
REQUEST_TIMEOUT = 30

TOKEN_ENV = "WALLET_PAY_TOKEN"

EXTERNAL_ID_PREFIX = "LVTI-INV-"


def is_configured() -> bool:
    return bool(os.environ.get(TOKEN_ENV, "").strip())


def _token() -> str:
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        raise RuntimeError(
            f"{TOKEN_ENV} not configured - get a store token at "
            f"https://pay.wallet.tg/ (requires KYB merchant approval)")
    return token


# --- signature scheme (mirrors the official reference implementation) -------


def compute_signature(store_api_key: str, http_method: str, uri_path: str,
                      timestamp: str | float, body: str | bytes) -> str:
    if not store_api_key:
        raise ValueError("store_api_key must not be empty")
    if isinstance(body, str):
        body = body.encode("utf-8")
    body_b64 = base64.b64encode(body).decode("utf-8")
    payload = f"{http_method}.{uri_path}.{timestamp}.{body_b64}"
    digest = hmac.new(store_api_key.encode("utf-8"), payload.encode("utf-8"),
                      hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def verify_webhook(store_api_key: str, http_method: str, uri_path: str,
                   timestamp: str, signature: str, raw_body: bytes) -> bool:
    if not timestamp or not signature:
        return False
    expected = compute_signature(store_api_key, http_method, uri_path,
                                 timestamp, raw_body)
    return compare_digest(signature, expected)


# --- webhook parsing ---------------------------------------------------------


def parse_webhook(raw_body: bytes | str) -> list[dict]:
    """Parse a Wallet Pay webhook body into a list of message dicts.
    Raises ValueError on structurally invalid bodies."""
    if isinstance(raw_body, bytes):
        raw_body = raw_body.decode("utf-8")
    data = json.loads(raw_body)  # ValueError/JSONDecodeError propagate
    if isinstance(data, dict):  # tolerate single-message bodies
        data = [data]
    if not isinstance(data, list):
        raise ValueError("webhook body must be a message list")
    messages = []
    for msg in data:
        if not isinstance(msg, dict):
            raise ValueError("webhook message must be an object")
        if msg.get("type") not in ("ORDER_PAID", "ORDER_FAILED"):
            continue  # unknown future event types are ignored, not fatal
        payload = msg.get("payload") or {}
        messages.append({
            "type": msg["type"],
            "event_id": msg.get("eventId"),
            "wallet_order_id": payload.get("id"),
            "number": payload.get("number"),
            "external_id": payload.get("externalId"),
            "status": payload.get("status"),
            "amount": (payload.get("orderAmount") or {}).get("amount"),
            "currency": (payload.get("orderAmount") or {}).get("currencyCode"),
        })
    return messages


def invoice_id_from_external_id(external_id: str | None) -> int | None:
    """'LVTI-INV-42' -> 42; anything else -> None."""
    if not external_id or not external_id.startswith(EXTERNAL_ID_PREFIX):
        return None
    tail = external_id[len(EXTERNAL_ID_PREFIX):]
    return int(tail) if tail.isdigit() else None


# --- store API client (sync; the product stack is requests-based) ------------


class WalletPayError(RuntimeError):
    pass


class WalletPayClient:
    """Thin sync client for the Wallet Pay store API."""

    def __init__(self, token: str, api_host: str = DEFAULT_API_HOST):
        self._token = token
        self._host = api_host.rstrip("/")

    def _headers(self) -> dict:
        return {AUTH_HEADER: self._token, "Content-Type": "application/json"}

    def create_order(self, amount: float | str, currency_code: str,
                     description: str, external_id: str,
                     timeout_seconds: int = 3600,
                     customer_telegram_user_id: int | None = None,
                     return_url: str | None = None,
                     fail_return_url: str | None = None,
                     custom_data: str | None = None) -> dict:
        """Create a payment order. Returns {'order_id', 'pay_link',
        'status', 'raw'}."""
        body: dict = {
            "amount": {"amount": str(amount), "currencyCode": currency_code},
            "description": description,
            "externalId": external_id,
            "timeoutSeconds": int(timeout_seconds),
        }
        if customer_telegram_user_id is not None:
            body["customerTelegramUserId"] = int(customer_telegram_user_id)
        if return_url:
            body["returnUrl"] = return_url
        if fail_return_url:
            body["failReturnUrl"] = fail_return_url
        if custom_data:
            body["customData"] = custom_data

        resp = requests.post(f"{self._host}/wpay/store-api/v1/order",
                             json=body, headers=self._headers(),
                             timeout=REQUEST_TIMEOUT)
        if resp.status_code in (400, 401, 403, 404, 429, 500):
            raise WalletPayError(
                f"wallet pay create_order failed: HTTP {resp.status_code} "
                f"{resp.text[:200]}")
        resp.raise_for_status()
        out = resp.json()
        if out.get("status") != "SUCCESS" or not out.get("data"):
            raise WalletPayError(
                f"wallet pay order rejected: {out.get('status')} "
                f"{out.get('message')}")
        data = out["data"]
        return {"order_id": data.get("id"), "pay_link": data.get("payLink"),
                "status": data.get("status"), "raw": data}

    def get_preview(self, order_id: str) -> dict:
        resp = requests.get(
            f"{self._host}/wpay/store-api/v1/order-preview/{order_id}",
            headers=self._headers(), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()


def client_from_env() -> WalletPayClient:
    return WalletPayClient(_token())
