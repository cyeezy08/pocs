"""The monetization layer - Gumroad license keys -> Discord subscriber role.

The feed business in one file:

  free lane  - public digest channel, daily, carries the buy CTA (marketing)
  paid lane  - LT_DISCORD_WEBHOOK_PAID, P0/P1 realtime (the product)
  the gate   - /subscribe <license>: every activation is verified LIVE against
               the Gumroad API; the local store only remembers which Discord
               user id each license is bound to, so one key cannot be shared
               across users silently.

Honesty rules (same discipline as the rest of the package):
  - verification always goes server-side to api.gumroad.com; the store is
    never trusted as proof of payment on its own.
  - cancelled/refunded/chargebacked purchases fail verification and the
    previously granted role is revoked on the spot.
  - network failure never silently degrades to "allow"; it fails with the
    reason stated.
  - /subscribe and /subscription replies are ephemeral - license keys are
    never posted into a channel.

Everything is injectable for tests: transports, env, time. Stdlib only.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from . import config
from .http import (http_delete, http_post_form, http_put_json, TransportError)

STORE_SCHEMA = 1
EPHEMERAL_FLAGS = config.EPHEMERAL_FLAGS  # alias; single source of truth in config


class LicenseBoundError(Exception):
    """The license key is already bound to a different Discord user."""


# ------------------------------------------------------------------ gumroad
def verify_license(license_key: str, permalink: str,
                   transport=None, timeout: float = config.GUMROAD_TIMEOUT_SECONDS) -> dict:
    """Verify a license key against the Gumroad API.

    -> normalized dict:
       ok          bool  - purchase exists AND is paid AND not cancelled/refunded
       error       str|None - human-readable reason when not ok (or on network failure)
       email, product, sale_id - provenance for the subscriber record
    Never raises on HTTP-level failures; TransportError is reported as
    {"ok": False, "error": ...} because the caller must not treat
    "Gumroad unreachable" as either valid or invalid.
    """
    fields = {"product_permalink": permalink, "license_key": license_key.strip()}
    try:
        r = http_post_form(config.GUMROAD_VERIFY_URL, fields, timeout=timeout,
                           transport=transport)
    except TransportError as e:
        return {"ok": False, "error": f"cannot reach gumroad: {e}",
                "email": None, "product": None, "sale_id": None}
    try:
        body = r.json()
    except (ValueError, json.JSONDecodeError):
        return {"ok": False, "error": f"gumroad returned non-JSON (HTTP {r.status})",
                "email": None, "product": None, "sale_id": None}
    if r.status == 404 or (isinstance(body, dict) and body.get("success") is False
                           and "not found" in str(body.get("message", "")).lower()):
        return {"ok": False, "error": "license not found - check the key",
                "email": None, "product": None, "sale_id": None}
    if not isinstance(body, dict) or body.get("success") is not True:
        msg = body.get("message") if isinstance(body, dict) else None
        return {"ok": False, "error": f"gumroad rejected the key (HTTP {r.status}"
                                      f"{': ' + msg if msg else ''})",
                "email": None, "product": None, "sale_id": None}
    purchase = body.get("purchase") or {}
    email = purchase.get("email")
    product = purchase.get("product_name")
    sale_id = str(purchase.get("sale_id") or "") or None
    refunded = bool(purchase.get("refunded"))
    chargebacked = bool(purchase.get("chargebacked"))
    cancelled = bool(purchase.get("subscription_cancelled_at"))
    if refunded:
        return {"ok": False, "error": "purchase was refunded - access denied",
                "email": email, "product": product, "sale_id": sale_id}
    if chargebacked:
        return {"ok": False, "error": "purchase was chargebacked - access denied",
                "email": email, "product": product, "sale_id": sale_id}
    if cancelled:
        return {"ok": False, "error": "subscription is cancelled - resubscribe to regain access",
                "email": email, "product": product, "sale_id": sale_id}
    return {"ok": True, "error": None, "email": email, "product": product,
            "sale_id": sale_id}


# --------------------------------------------------------------------- store
class SubscriberStore:
    """License -> Discord binding. JSON file, atomic writes, survives cron."""

    def __init__(self, path):
        self.path = Path(path)
        self.subs: dict = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            if doc.get("schema") == STORE_SCHEMA:
                self.subs = dict(doc.get("subs", {}))
        except (json.JSONDecodeError, ValueError, OSError):
            self.subs = {}  # corrupt -> start clean; re-verification is one /subscribe away

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"schema": STORE_SCHEMA, "subs": self.subs},
                                  indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def get_by_license(self, license_key: str):
        return self.subs.get(license_key.strip())

    def get_by_discord(self, discord_id: str):
        for rec in self.subs.values():
            if rec.get("discord_id") == str(discord_id):
                return rec
        return None

    def bind(self, license_key: str, discord_id: str, username: str,
             email, product) -> dict:
        key = license_key.strip()
        existing = self.subs.get(key)
        if existing and existing.get("discord_id") != str(discord_id):
            raise LicenseBoundError(
                "this license is already bound to another Discord account")
        rec = {"discord_id": str(discord_id), "username": username,
               "email": email, "product": product,
               "activated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self.subs[key] = rec
        self.save()
        return rec

    def unbind(self, license_key: str) -> None:
        if license_key.strip() in self.subs:
            del self.subs[license_key.strip()]
            self.save()

    def license_for_discord(self, discord_id: str):
        rec = self.get_by_discord(discord_id)
        if not rec:
            return None
        for k, v in self.subs.items():
            if v is rec:
                return k
        return None


# ------------------------------------------------------------------ discord
def _role_url(guild_id: str, user_id: str, role_id: str) -> str:
    return (f"{config.DISCORD_API_BASE}"
            f"/guilds/{guild_id}/members/{user_id}/roles/{role_id}")


def grant_role(bot_token: str, guild_id: str, user_id: str, role_id: str,
               transport=None) -> None:
    """PUT the subscriber role. 204 = granted. Raises TransportError/ValueError."""
    r = http_put_json(_role_url(guild_id, user_id, role_id), {},
                      headers={"Authorization": f"Bot {bot_token}"},
                      transport=transport)
    if r.status not in (200, 204):
        raise ValueError(f"role grant failed (HTTP {r.status}) - check that the "
                         "bot has Manage Roles and outranks the subscriber role")


def revoke_role(bot_token: str, guild_id: str, user_id: str, role_id: str,
                transport=None) -> None:
    """DELETE the subscriber role. 404 is tolerated (already gone / left guild)."""
    r = http_delete(_role_url(guild_id, user_id, role_id),
                    headers={"Authorization": f"Bot {bot_token}"},
                    transport=transport)
    if r.status not in (200, 204, 404):
        raise ValueError(f"role revoke failed (HTTP {r.status})")


# ------------------------------------------------------------------- facade
class Paywall:
    """Everything /subscribe needs, injectable end to end.

    Built from env in cli.cmd_gateway; when LT_GUMROAD_PERMALINK is unset,
    from_env returns None and the bot answers /subscribe with an honest
    'paywall not configured' instead of pretending.
    """

    def __init__(self, store, permalink: str, bot_token: str = "",
                 guild_id: str = "", role_id: str = "",
                 transport=None, role_transport=None, now=None):
        self.store = store
        self.permalink = permalink
        self.bot_token = bot_token
        self.guild_id = guild_id
        self.role_id = role_id
        self.transport = transport          # gumroad transport
        self.role_transport = role_transport  # discord REST transport
        self.now = now or time.time

    @classmethod
    def from_env(cls, env=None, store_path=None) -> Optional["Paywall"]:
        env = env if env is not None else os.environ
        permalink = env.get(config.ENV_GUMROAD_PERMALINK, "").strip()
        if not permalink:
            return None
        return cls(
            store=SubscriberStore(store_path),
            permalink=permalink,
            bot_token=env.get(config.ENV_BOT_TOKEN, ""),
            guild_id=env.get(config.ENV_DISCORD_GUILD_ID, "").strip(),
            role_id=env.get(config.ENV_DISCORD_ROLE_ID, "").strip(),
        )

    # ------------------------------------------------------------ subscribe
    def subscribe(self, license_key: str, discord_id: str,
                  username: str = "user") -> dict:
        """Full activation flow -> normalized result for the command layer."""
        key = (license_key or "").strip()
        if len(key) < config.LICENSE_MIN_LENGTH:
            return {"ok": False, "message": "that does not look like a license key "
                                            f"(expected the long key from your Gumroad receipt)"}
        existing = self.store.get_by_license(key)
        if existing and existing.get("discord_id") != str(discord_id):
            return {"ok": False,
                    "message": "this license is already bound to another Discord account"}
        verdict = verify_license(key, self.permalink, transport=self.transport)
        if not verdict["ok"]:
            return {"ok": False, "message": verdict["error"]}
        if existing:
            msg = "already active - role re-checked"
        else:
            self.store.bind(key, discord_id, username, verdict["email"],
                            verdict["product"])
            msg = "subscribed - realtime P0/P1 alerts unlocked"
        role_error = None
        if self.guild_id and self.role_id and self.bot_token:
            try:
                grant_role(self.bot_token, self.guild_id, str(discord_id),
                           self.role_id, transport=self.role_transport)
            except (TransportError, ValueError) as e:
                role_error = str(e)
        return {"ok": True, "message": msg, "email": verdict["email"],
                "product": verdict["product"], "role_granted": role_error is None,
                "role_error": role_error}

    # -------------------------------------------------------------- revoke
    def revoke_for_license(self, license_key: str) -> dict:
        """Cancelled/refunded/chargebacked found during verification -> strip role."""
        rec = self.store.get_by_license(license_key)
        self.store.unbind(license_key)
        if rec and self.guild_id and self.role_id and self.bot_token:
            try:
                revoke_role(self.bot_token, self.guild_id, rec["discord_id"],
                            self.role_id, transport=self.role_transport)
            except (TransportError, ValueError):
                pass  # best effort; the store is already unbound
        return {"revoked": True, "had_record": rec is not None}

    # -------------------------------------------------------------- status
    def status(self, discord_id: str) -> dict:
        rec = self.store.get_by_discord(discord_id)
        if not rec:
            return {"active": False}
        # re-verify on every status check: a store entry alone is not proof
        key = self.license_key_for(discord_id)
        verdict = verify_license(key, self.permalink, transport=self.transport) if key \
            else {"ok": False, "error": None}
        if not verdict["ok"]:
            if key:
                self.revoke_for_license(key)
            return {"active": False, "reason": verdict.get("error")}
        return {"active": True, "email": rec.get("email"),
                "product": rec.get("product"), "since": rec.get("activated_at")}

    def license_key_for(self, discord_id: str):
        return self.store.license_for_discord(discord_id)
