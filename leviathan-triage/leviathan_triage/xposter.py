"""Huginn - the X/Twitter auto-poster. OAuth 1.0a user context, stdlib only.

The marketing raven: every day it carries the P0 digest out of the Discord
feed and drops it on X, with a link back to the free channel. It is a
POSTER, not a reader: free-tier API has no useful read access anyway, and a
bot that never reads never gets baited into engagement farming.

Signing discipline (RFC 5849 + X's percent-encoding rules):
  - unreserved chars: A-Z a-z 0-9 - . _ ~  (urllib quote with safe="-._~")
  - signature base = METHOD & pE(base_url) & pE(sorted param string)
  - JSON request bodies contribute NO signature params (only form bodies do)
  - signing key = pE(consumer_secret) & pE(token_secret)
  - nonce/timestamp injectable for known-answer tests

Honesty rules:
  - credentials come from env only, are never logged, never echoed
  - 401/403 surface as actionable errors (bad token / no write access)
  - 429 surfaces with the reset epoch so cron can back off
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from typing import Optional

from . import config
from .http import Response, http_get, http_post_json, TransportError


class XApiError(Exception):
    """X API returned an error worth reading (auth, tier, rate limit)."""


# ------------------------------------------------------------------ encoding
def percent_encode(s: str) -> str:
    return urllib.parse.quote(s or "", safe="-._~")


# ------------------------------------------------------------------ signing
def oauth_signature(method: str, base_url: str, params: dict,
                    consumer_secret: str, token_secret: str = "") -> str:
    """RFC 5849 §3.4 HMAC-SHA1 signature over a prepared param dict.

    `params` holds BOTH oauth_* protocol params and any form body params,
    exactly as they appear in the param string. Pure function - the golden
    vector test lives in tests/test_xposter.py.
    """
    encoded = sorted((percent_encode(k), percent_encode(str(v)))
                     for k, v in params.items())
    param_str = "&".join(f"{k}={v}" for k, v in encoded)
    base = "&".join([method.upper(), percent_encode(base_url),
                     percent_encode(param_str)])
    key = f"{percent_encode(consumer_secret)}&{percent_encode(token_secret)}"
    digest = hmac.new(key.encode("utf-8"), base.encode("utf-8"),
                      hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii")


def oauth_header(method: str, url: str, consumer_key: str,
                 consumer_secret: str, token: str = "",
                 token_secret: str = "", extra_params: Optional[dict] = None,
                 nonce: Optional[str] = None, timestamp: Optional[str] = None,
                 body_params: Optional[dict] = None) -> str:
    """Build the full Authorization header. nonce/timestamp injectable for tests."""
    params = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": nonce or base64.b64encode(os.urandom(24)).decode("ascii"),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": timestamp or str(int(time.time())),
        "oauth_version": "1.0",
    }
    if token:
        params["oauth_token"] = token
    if extra_params:
        params.update(extra_params)
    merged = dict(params)
    if body_params:  # only form-encoded bodies join the signature; JSON never does
        merged.update(body_params)
    sig = oauth_signature(method, url, merged, consumer_secret, token_secret)
    out = dict(params)
    out["oauth_signature"] = sig
    return "OAuth " + ", ".join(f'{percent_encode(k)}="{percent_encode(str(v))}"'
                                for k, v in sorted(out.items()))


def _extract_base_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def header_for_request(method: str, url: str, creds: dict,
                       nonce=None, timestamp=None) -> str:
    """Authorization header for a real endpoint call (JSON body path)."""
    return oauth_header(method, _extract_base_url(url),
                        creds["consumer_key"], creds["consumer_secret"],
                        token=creds.get("access_token", ""),
                        token_secret=creds.get("access_secret", ""),
                        nonce=nonce, timestamp=timestamp)


# ----------------------------------------------------------------- requests
def _creds_from_env(env=None, need_user_tokens: bool = True) -> dict:
    env = env if env is not None else os.environ
    creds = {
        "consumer_key": env.get(config.ENV_X_CONSUMER_KEY, "").strip(),
        "consumer_secret": env.get(config.ENV_X_CONSUMER_SECRET, "").strip(),
        "access_token": env.get(config.ENV_X_ACCESS_TOKEN, "").strip(),
        "access_secret": env.get(config.ENV_X_ACCESS_SECRET, "").strip(),
    }
    if not creds["consumer_key"] or not creds["consumer_secret"]:
        raise XApiError(f"missing {config.ENV_X_CONSUMER_KEY}/"
                        f"{config.ENV_X_CONSUMER_SECRET}")
    if need_user_tokens and (not creds["access_token"] or not creds["access_secret"]):
        raise XApiError(
            "missing user access tokens - developer.x.com -> your app -> Keys "
            f"and tokens -> generate OAuth 1.0a Access Token + Secret, then set "
            f"{config.ENV_X_ACCESS_TOKEN}/{config.ENV_X_ACCESS_SECRET}")
    return creds


def _raise_for_status(r: Response, action: str) -> dict:
    try:
        body = r.json()
    except (ValueError, json.JSONDecodeError):
        body = {}
    if r.status == 429:
        reset = r.headers.get("x-rate-limit-reset", "?")
        raise XApiError(f"rate limited (429) - window resets at epoch {reset}; "
                        "free tier is write-capped, keep the cadence at 1/day")
    if r.status in (401, 403):
        detail = body.get("detail") or body.get("errors") or ""
        raise XApiError(f"{action} denied (HTTP {r.status}): {detail} - check the "
                        "user access tokens, app permissions (Read+Write), and "
                        "that the tokens belong to THIS app")
    if r.status not in (200, 201):
        raise XApiError(f"{action} failed (HTTP {r.status}): "
                        f"{r.body[:200].decode('utf-8', errors='replace')}")
    return body


def verify_credentials(env=None, transport=None) -> dict:
    """GET /2/users/me with OAuth 1.0a user context - validates the full pair."""
    creds = _creds_from_env(env)
    url = f"{config.X_ME_ENDPOINT}?user.fields=username"
    headers = {"Authorization": header_for_request("GET", url, creds)}
    r = http_get(url, headers=headers, transport=transport,
                 timeout=config.X_TIMEOUT_SECONDS)
    body = _raise_for_status(r, "verify")
    return body.get("data", {})


def request_token(consumer_key: str, consumer_secret: str,
                  transport=None) -> dict:
    """OAuth 1.0a request-token probe - validates the CONSUMER pair with zero
    side effects (unused request tokens expire in minutes). oob callback."""
    header = oauth_header("POST", config.X_REQUEST_TOKEN_ENDPOINT,
                          consumer_key, consumer_secret,
                          extra_params={"oauth_callback": "oob"})
    r = http_post_json(config.X_REQUEST_TOKEN_ENDPOINT, {},
                       headers={"Authorization": header}, transport=transport,
                       timeout=config.X_TIMEOUT_SECONDS)
    if r.status == 401:
        raise XApiError("consumer key/secret rejected (HTTP 401) - wrong or revoked")
    if r.status != 200:
        raise XApiError(f"request_token failed (HTTP {r.status})")
    fields = dict(urllib.parse.parse_qsl(r.body.decode("utf-8", errors="replace")))
    if not fields.get("oauth_callback_confirmed"):
        raise XApiError("callback not confirmed - unexpected response")
    return {"oauth_token": fields.get("oauth_token", ""),
            "oauth_token_secret": fields.get("oauth_token_secret", ""),
            "confirmed": True}


def post_tweet(text: str, env=None, transport=None) -> dict:
    """POST /2/tweets (OAuth 1.0a user context, JSON body). Returns {'id','text'}."""
    creds = _creds_from_env(env)
    headers = {"Authorization": header_for_request("POST", config.X_TWEET_ENDPOINT,
                                                   creds)}
    r = http_post_json(config.X_TWEET_ENDPOINT, {"text": text},
                       headers=headers, transport=transport,
                       timeout=config.X_TIMEOUT_SECONDS)
    body = _raise_for_status(r, "post")
    data = body.get("data") or {}
    return {"id": data.get("id", ""), "text": data.get("text", text)}


# ------------------------------------------------------------------ compose
def compose_post(findings: list, link: str = "",
                 max_chars: int = config.X_POST_MAX_CHARS) -> Optional[str]:
    """One honest post from the current queue. None = nothing worth posting.

    X charges 23 chars for every URL; counts are exact by construction:
    len(link) is replaced with X_URL_DISPLAY_CHARS when measuring.
    """
    hot = [f for f in findings if f.band in config.SUBSCRIBER_BANDS]
    if not hot:
        return None
    hot = sorted(hot, key=lambda f: -f.score)
    counts: dict = {}
    for f in findings:
        counts[f.band] = counts.get(f.band, 0) + 1

    def measure(lines: list) -> int:
        return sum((config.X_URL_DISPLAY_CHARS if link and link in l
                    else len(l)) + 1 for l in lines) - 1

    head = (f"KEV watch: {len(hot)} exploited-in-the-wild CVE(s) matched "
            f"common stacks ({', '.join(f'{b}x{counts[b]}' for b in config.BANDS if b in counts)})")
    tail = f"triage yours free: {link}" if link else "triage yours free"

    body = []
    for f in hot:
        body.append(f"{f.band} {f.cve} {f.score:g}/100 - "
                    f"{f.title or f.asset.identifier}"[:100] +
                    (" +ransomware" if f.known_ransomware else ""))
        if measure([head] + body + [tail]) > max_chars:
            body.pop()
            break
    if not body:
        body = [f"{hot[0].band} {hot[0].cve} {hot[0].score:g}/100"]
    lines = [head] + body + ([tail] if tail else [])
    while measure(lines) > max_chars and len(body) > 1:
        body.pop()
        lines = [head] + body + ([tail] if tail else [])
    return "\n".join(lines)
