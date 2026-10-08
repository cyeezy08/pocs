"""xapi: OAuth 1.0a signature validated against the documented Twitter test
vector, plus request behavior with stubbed transport."""

from __future__ import annotations

import json

import pytest

from huginn import config, xapi


def test_signature_matches_documented_test_vector():
    """Twitter's published OAuth 1.0a example (status update endpoint).

    creds/params from https://docs.twitter.com - the HMAC-SHA1 result must be
    exactly hCtSmYh+iHYCEqBWrE7C7hYmtUk= - any drift in percent-encoding,
    param sorting, or base-string construction breaks this.
    """
    creds = {
        "api_key": "xvz1evFS4wEEPTGEFPHBog",
        "api_secret": "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
        "access_token": "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
        "access_secret": "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
    }
    params = {
        "status": "Hello Ladies + Gentlemen, a signed OAuth request!",
        "include_entities": "true",
    }
    header = xapi.oauth_header(
        "POST",
        "https://api.twitter.com/1.1/statuses/update.json",
        params,
        creds,
        timestamp="1318622958",
        nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
    )
    assert 'oauth_signature="hCtSmYh%2BiHYCEqBWrE7C7hYmtUk%3D"' in header


def test_pct_uses_rfc3986_unreserved():
    assert xapi._pct("a b+c/d~e.f-g_h") == "a%20b%2Bc%2Fd~e.f-g_h"
    assert xapi._pct("~") == "~"


def test_missing_creds_raise_xauth_error(clean_env):
    with pytest.raises(xapi.XAuthError):
        xapi.post_tweet("hello")


def test_post_tweet_success_with_stub(clean_env, monkeypatch):
    monkeypatch.setenv(config.ENV_X_KEY, "k")
    monkeypatch.setenv(config.ENV_X_SECRET, "s")
    monkeypatch.setenv(config.ENV_X_TOKEN, "t")
    monkeypatch.setenv(config.ENV_X_TOKEN_SECRET, "ts")

    captured = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({"data": {"id": "123", "text": "hi"}}).encode()

    def fake_urlopen(req, timeout=30):
        captured["auth"] = req.headers["Authorization"]
        captured["body"] = req.data
        return FakeResp()

    result = xapi.post_tweet("hi", post=fake_urlopen)
    assert result["data"]["id"] == "123"
    assert captured["auth"].startswith("OAuth ")
    assert "oauth_signature=" in captured["auth"]
    assert json.loads(captured["body"]) == {"text": "hi"}


def test_http_429_maps_to_ratelimit(clean_env, monkeypatch):
    import urllib.error

    for var, val in [
        (config.ENV_X_KEY, "k"), (config.ENV_X_SECRET, "s"),
        (config.ENV_X_TOKEN, "t"), (config.ENV_X_TOKEN_SECRET, "ts"),
    ]:
        monkeypatch.setenv(var, val)

    def fake_urlopen(req, timeout=30):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)

    with pytest.raises(xapi.XRateLimit):
        xapi.post_tweet("hi", post=fake_urlopen)


def test_http_403_maps_to_auth_error(clean_env, monkeypatch):
    import urllib.error

    for var, val in [
        (config.ENV_X_KEY, "k"), (config.ENV_X_SECRET, "s"),
        (config.ENV_X_TOKEN, "t"), (config.ENV_X_TOKEN_SECRET, "ts"),
    ]:
        monkeypatch.setenv(var, val)

    def fake_urlopen(req, timeout=30):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)

    with pytest.raises(xapi.XAuthError):
        xapi.post_tweet("hi", post=fake_urlopen)


def test_refuses_empty_or_huge_text(clean_env, monkeypatch):
    monkeypatch.setenv(config.ENV_X_KEY, "k")
    with pytest.raises(xapi.XApiError):
        xapi.post_tweet("")
    with pytest.raises(xapi.XApiError):
        xapi.post_tweet("x" * 1000)
