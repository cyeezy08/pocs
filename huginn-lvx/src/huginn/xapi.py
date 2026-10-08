"""X API v2 tweet posting via OAuth 1.0a (stdlib only: hmac + urllib).

Percent-encoding per RFC 3986 unreserved set, params sorted byte-wise,
HMAC-SHA1 over POST&url&params - validated against the documented Twitter
signature test vector in tests/test_xapi.py.

DRY-RUN IS THE DEFAULT ANYWHERE IT MATTERS: cli.post prints unless --yes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from . import config


def _pct(s: str) -> str:
    return urllib.parse.quote(s, safe="-._~")


def _nonce() -> str:
    return secrets.token_hex(16)


def oauth_header(
    method: str,
    url: str,
    params: dict[str, str],
    creds: dict[str, str],
    timestamp: str | None = None,
    nonce: str | None = None,
) -> str:
    """Build the Authorization header. timestamp/nonce injectable for tests."""
    oauth_params = {
        "oauth_consumer_key": creds["api_key"],
        "oauth_nonce": nonce or _nonce(),
        "oauth_signature_method": config.X_OAUTH_PARAMS["oauth_signature_method"],
        "oauth_timestamp": timestamp or str(int(time.time())),
        "oauth_token": creds["access_token"],
        "oauth_version": config.X_OAUTH_PARAMS["oauth_version"],
    }
    all_params = {**params, **oauth_params}
    param_str = "&".join(
        f"{_pct(k)}={_pct(v)}" for k, v in sorted(all_params.items())
    )
    base_url = url.split("?")[0]
    base = "&".join([method.upper(), _pct(base_url), _pct(param_str)])
    key = f"{_pct(creds['api_secret'])}&{_pct(creds['access_secret'])}"
    digest = hmac.new(key.encode(), base.encode(), hashlib.sha1).digest()
    oauth_params["oauth_signature"] = base64.b64encode(digest).decode()
    header = "OAuth " + ", ".join(f'{_pct(k)}="{_pct(v)}"' for k, v in sorted(oauth_params.items()))
    return header


def _creds() -> dict[str, str]:
    creds = {
        "api_key": os.environ.get(config.ENV_X_KEY, ""),
        "api_secret": os.environ.get(config.ENV_X_SECRET, ""),
        "access_token": os.environ.get(config.ENV_X_TOKEN, ""),
        "access_secret": os.environ.get(config.ENV_X_TOKEN_SECRET, ""),
    }
    missing = [k for k, v in creds.items() if not v]
    if missing:
        raise XAuthError(f"missing X credentials in env: {', '.join(missing)}")
    return creds


def post_tweet(text: str, post=None) -> dict:
    """POST /2/tweets. Returns {"data": {"id": ..., "text": ...}} on success."""
    if not text or len(text) > config.MAX_POST_CHARS * 2:
        raise XApiError("refusing to post: text empty or absurdly long")
    creds = _creds()
    body = json.dumps({"text": text}).encode("utf-8")
    url = config.X_TWEET_URL
    header = oauth_header("POST", url, {}, creds)
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": header,
            "Content-Type": "application/json",
            "User-Agent": "huginn-lvx",
        },
        method="POST",
    )
    do_post = post or urllib.request.urlopen
    try:
        with do_post(req, timeout=30) as resp:  # type: ignore[operator]
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        if e.code in (401, 403):
            raise XAuthError(f"X rejected credentials (HTTP {e.code}): {detail}") from e
        if e.code == 429:
            raise XRateLimit(f"rate limited (HTTP 429): {detail}") from e
        raise XApiError(f"X API error {e.code}: {detail}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise XApiError(f"network error: {e}") from e


class XApiError(RuntimeError):
    pass


class XAuthError(XApiError):
    pass


class XRateLimit(XApiError):
    pass
