"""Leviathan Intel API - FastAPI delivery tier.

v0.1 auth: single admin bearer token (ADMIN_TOKEN env). Per-tenant API keys
exist in the schema; enforcement lands with the dashboard milestone.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from billing import wallet_pay as wp
from billing.invoices import (
    gen_memo,
    pay_instructions,
    resolve_address,
    validate_currency,
)

DB_CONF = dict(
    dbname=os.environ.get("DB_NAME", "leviathan"),
    user=os.environ.get("DB_USER", "postgres"),
    password=os.environ.get("DB_PASS", "postgres"),
    host=os.environ.get("DB_HOST", "localhost"),
    port=os.environ.get("DB_PORT", "5432"),
)


def get_db():
    conn = psycopg.connect(**DB_CONF)
    try:
        yield conn
    finally:
        conn.close()


def require_admin(authorization: str = Header(default="")) -> None:
    token = os.environ.get("ADMIN_TOKEN", "")
    if not token:
        raise HTTPException(503, "ADMIN_TOKEN not configured")
    supplied = authorization.removeprefix("Bearer ").strip()
    if supplied != token:
        raise HTTPException(401, "invalid token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="Leviathan Intel", version="0.1.0", lifespan=lifespan)


class TenantIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    plan: str = Field(default="trial", pattern="^(trial|starter|pro)$")


class AssetIn(BaseModel):
    tenant_id: int
    kind: str = Field(pattern="^(domain|ip|service)$")
    value: str = Field(min_length=3, max_length=255)
    cpe: str | None = None


@app.get("/health")
def health():
    return {"ok": True, "service": "leviathan-intel", "version": "0.1.0"}


@app.post("/tenants", status_code=201, dependencies=[Depends(require_admin)])
def create_tenant(t: TenantIn, conn=Depends(get_db)):
    import secrets

    token = secrets.token_urlsafe(32)
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (name, plan, api_token) VALUES (%s, %s, %s) RETURNING id",
            (t.name, t.plan, token),
        )
        tenant_id = cur.fetchone()[0]
    conn.commit()
    return {"id": tenant_id, "api_token": token}


@app.post("/assets", status_code=201, dependencies=[Depends(require_admin)])
def register_asset(a: AssetIn, conn=Depends(get_db)):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO assets (tenant_id, kind, value, cpe)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (tenant_id, kind, value) DO UPDATE SET last_seen = now()
            RETURNING id
            """,
            (a.tenant_id, a.kind, a.value, a.cpe),
        )
        asset_id = cur.fetchone()[0]
    conn.commit()
    return {"id": asset_id}


@app.get("/findings", dependencies=[Depends(require_admin)])
def findings(tenant_id: int, min_priority: int = 35, limit: int = 100,
             conn=Depends(get_db)):
    if not 0 <= min_priority <= 100:
        raise HTTPException(422, "min_priority must be 0-100")
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT f.id, a.value AS asset, a.cpe, f.cve_id, f.priority, f.reasons,
                   f.status, c.severity, c.kev
              FROM findings f
              JOIN assets a ON a.id = f.asset_id
              JOIN cves   c ON c.cve_id = f.cve_id
             WHERE a.tenant_id = %s AND f.priority >= %s
             ORDER BY f.priority DESC
             LIMIT %s
            """,
            (tenant_id, min_priority, min(limit, 500)),
        )
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


@app.get("/stats", dependencies=[Depends(require_admin)])
def stats(tenant_id: int, conn=Depends(get_db)):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT count(*)                                              AS total,
                   count(*) FILTER (WHERE priority >= 80)                AS critical,
                   count(*) FILTER (WHERE priority >= 60 AND priority < 80) AS high,
                   count(*) FILTER (WHERE c.kev)                         AS kev_related
              FROM findings f
              JOIN assets a ON a.id = f.asset_id
              JOIN cves   c ON c.cve_id = f.cve_id
             WHERE a.tenant_id = %s
            """,
            (tenant_id,),
        )
        row = cur.fetchone()
        cols = [d.name for d in cur.description]
        return dict(zip(cols, row))


# --------------------------------------------------------------------------
# Beta billing - crypto invoices with manual reconciliation.
# Flow: POST /billing/invoices  -> customer gets pay_to + amount + memo
#       (USDT lands in YOUR wallet - Telegram Wallet, self-custody, whatever
#       you control) -> POST /billing/invoices/{id}/paid unlocks the plan.
# --------------------------------------------------------------------------


class InvoiceIn(BaseModel):
    tenant_id: int
    plan: str = Field(pattern="^(trial|starter|pro)$")
    amount_usd: float = Field(ge=0, le=100000)
    currency: str = Field(default="USDT-TON")


class PaidIn(BaseModel):
    tx_ref: str | None = Field(default=None, max_length=200)


def _require_pay_address(currency: str) -> str:
    try:
        return resolve_address(currency)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))


@app.post("/billing/invoices", status_code=201,
          dependencies=[Depends(require_admin)])
def create_invoice(inv: InvoiceIn, conn=Depends(get_db)):
    try:
        currency = validate_currency(inv.currency)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    address = _require_pay_address(currency)

    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM tenants WHERE id = %s", (inv.tenant_id,))
        if cur.fetchone() is None:
            raise HTTPException(404, f"tenant {inv.tenant_id} does not exist")

        cur.execute(
            """
            INSERT INTO invoices (tenant_id, plan, amount_usd, currency,
                                  address, memo, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, now() + interval '3 days')
            RETURNING id, memo, expires_at
            """,
            (inv.tenant_id, inv.plan, inv.amount_usd, currency, address,
             gen_memo()),
        )
        inv_id, memo, expires_at = cur.fetchone()
    conn.commit()

    return pay_instructions({
        "id": inv_id, "memo": memo, "address": address, "currency": currency,
        "amount_usd": inv.amount_usd, "plan": inv.plan,
        "expires_at": expires_at,
    })


@app.get("/billing/invoices", dependencies=[Depends(require_admin)])
def list_invoices(tenant_id: int, conn=Depends(get_db)):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, plan, amount_usd, currency, address, memo, status,
                   tx_ref, expires_at, paid_at, created_at
              FROM invoices
             WHERE tenant_id = %s
             ORDER BY id DESC
            """,
            (tenant_id,),
        )
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


@app.post("/billing/invoices/{invoice_id}/paid",
          dependencies=[Depends(require_admin)])
def mark_paid(invoice_id: int, body: PaidIn, conn=Depends(get_db)):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE invoices
               SET status = 'paid',
                   tx_ref = COALESCE(%s, tx_ref),
                   paid_at = now()
             WHERE id = %s
               AND status = 'waiting'
               AND expires_at > now()
            RETURNING tenant_id, plan
            """,
            (body.tx_ref, invoice_id),
        )
        row = cur.fetchone()
        if row is None:
            cur.execute(
                "SELECT status FROM invoices WHERE id = %s", (invoice_id,))
            found = cur.fetchone()
            if found is None:
                raise HTTPException(404, f"invoice {invoice_id} not found")
            status = found[0]
            if status == "paid":
                raise HTTPException(409, "invoice already paid")
            raise HTTPException(409, f"invoice not payable (status: {status})")

        tenant_id, plan = row
        cur.execute(
            "UPDATE tenants SET plan = %s WHERE id = %s", (plan, tenant_id))
    conn.commit()
    return {"ok": True, "tenant_id": tenant_id, "plan": plan,
            "note": f"tenant {tenant_id} promoted to '{plan}'"}


# ---------------------------------------------------------------------------
# Wallet Pay (optional auto-settle path). Requires WALLET_PAY_TOKEN from a
# KYB-approved store at https://pay.wallet.tg/. Manual invoices keep working
# without it. Webhook is PUBLIC but HMAC-verified per Wallet's scheme.
# ---------------------------------------------------------------------------


class WalletPayIn(BaseModel):
    customer_tg_id: int | None = None
    timeout_seconds: int = Field(default=3600, ge=300, le=86400)


@app.post("/billing/invoices/{invoice_id}/wallet-pay",
          dependencies=[Depends(require_admin)])
def create_wallet_pay_order(invoice_id: int, body: WalletPayIn,
                            conn=Depends(get_db)):
    if not wp.is_configured():
        raise HTTPException(
            503, "WALLET_PAY_TOKEN not configured (manual invoice flow "
                 "remains available)")

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, tenant_id, plan, amount_usd, memo, status
              FROM invoices WHERE id = %s
            """,
            (invoice_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, f"invoice {invoice_id} not found")
        inv_id, tenant_id, plan, amount_usd, memo, status = row
        if status != "waiting":
            raise HTTPException(409, f"invoice not payable (status: {status})")

        order = wp.client_from_env().create_order(
            amount=amount_usd,
            currency_code="USD",
            description=f"Leviathan Intel - {plan} plan (invoice {memo})",
            external_id=f"{wp.EXTERNAL_ID_PREFIX}{inv_id}",
            timeout_seconds=body.timeout_seconds,
            customer_telegram_user_id=body.customer_tg_id,
            custom_data=memo,
        )
        cur.execute(
            """
            UPDATE invoices SET wallet_order_id = %s, pay_link = %s
             WHERE id = %s
            """,
            (str(order["order_id"]), order["pay_link"], inv_id),
        )
    conn.commit()
    return {"invoice_id": inv_id, "wallet_order_id": order["order_id"],
            "pay_link": order["pay_link"],
            "note": "send the customer here; settlement arrives via webhook"}


@app.post("/webhooks/wallet-pay")
async def wallet_pay_webhook(request: Request):
    """Public endpoint - authenticity comes from the HMAC signature, not
    from network position. Non-matching signatures get 400, always.
    DB connection opens only after the cheap checks pass."""
    if not wp.is_configured():
        raise HTTPException(503, "wallet pay not configured")

    raw_body = await request.body()
    timestamp = request.headers.get("WalletPay-Timestamp", "")
    signature = request.headers.get("WalletPay-Signature", "")

    token = os.environ[wp.TOKEN_ENV]
    if not wp.verify_webhook(token, request.method,
                             request.url.path, timestamp, signature, raw_body):
        raise HTTPException(400, "signature verification failed")

    try:
        messages = wp.parse_webhook(raw_body)
    except ValueError as exc:
        raise HTTPException(422, str(exc))

    settled = []
    conn = psycopg.connect(**DB_CONF)
    try:
        with conn.cursor() as cur:
            for msg in messages:
                inv_id = wp.invoice_id_from_external_id(msg["external_id"])
                if inv_id is None:
                    continue
                if msg["type"] == "ORDER_PAID":
                    cur.execute(
                        """
                        UPDATE invoices
                           SET status = 'paid', paid_at = now(), tx_ref = %s
                         WHERE id = %s AND status = 'waiting'
                        RETURNING tenant_id, plan
                        """,
                        (f"wpay:{msg.get('wallet_order_id')}", inv_id),
                    )
                    promoted = cur.fetchone()
                    if promoted:
                        tenant_id, plan = promoted
                        cur.execute(
                            "UPDATE tenants SET plan = %s WHERE id = %s",
                            (plan, tenant_id))
                        settled.append({"invoice_id": inv_id,
                                        "action": f"promoted to {plan}"})
                elif msg["type"] == "ORDER_FAILED":
                    cur.execute(
                        """
                        UPDATE invoices
                           SET status = 'cancelled', tx_ref = %s
                         WHERE id = %s AND status = 'waiting'
                        """,
                        (f"wpay-failed:{msg.get('status')}", inv_id),
                    )
                    settled.append({"invoice_id": inv_id,
                                    "action": "marked cancelled"})
        conn.commit()
    finally:
        conn.close()
    return {"success": True, "processed": settled}
