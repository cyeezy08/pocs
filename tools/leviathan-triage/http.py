"""Minimal stdlib HTTP layer with injectable transports.

Every network touchpoint (feeds, webhook, gateway REST) goes through here so
tests can inject fake transports and the live code path stays stdlib-only.
No third-party dependency in this package. None.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import config


class TransportError(Exception):
    """Network-level failure (DNS, refused, TLS, timeout)."""


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: dict = field(default_factory=dict)

    def json(self):
        return json.loads(self.body.decode("utf-8", errors="replace"))


def _urllib_get(url: str, timeout: float, headers: dict) -> Response:
    req = urllib.request.Request(url, headers=headers, method="GET")
    return _do(req, timeout)


def _urllib_post_json(url: str, payload: dict, timeout: float, headers: dict) -> Response:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", **headers})
    return _do(req, timeout)


def _urllib_put_json(url: str, payload: dict, timeout: float, headers: dict) -> Response:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="PUT",
        headers={"Content-Type": "application/json", **headers})
    return _do(req, timeout)


def _urllib_post_form(url: str, fields: dict, timeout: float, headers: dict) -> Response:
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", **headers})
    return _do(req, timeout)


def _urllib_delete(url: str, timeout: float, headers: dict) -> Response:
    req = urllib.request.Request(url, method="DELETE", headers=headers)
    return _do(req, timeout)


def _do(req: urllib.request.Request, timeout: float) -> Response:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return Response(status=resp.status, body=resp.read(),
                            headers={k.lower(): v for k, v in resp.headers.items()})
    except urllib.error.HTTPError as e:
        # 4xx/5xx are readable responses; caller decides what is an error.
        return Response(status=e.code, body=e.read(),
                        headers={k.lower(): v for k, v in e.headers.items()})
    except urllib.error.URLError as e:
        raise TransportError(str(e.reason)) from e
    except (TimeoutError, OSError) as e:  # socket timeouts, connection resets
        raise TransportError(str(e)) from e


GetTransport = Callable[[str, float, dict], Response]
PostTransport = Callable[[str, dict, float, dict], Response]
PutTransport = Callable[[str, dict, float, dict], Response]
FormTransport = Callable[[str, dict, float, dict], Response]
DeleteTransport = Callable[[str, float, dict], Response]


def http_get(url: str, timeout: float = 60.0, headers: Optional[dict] = None,
             transport: Optional[GetTransport] = None) -> Response:
    """GET with a User-Agent that identifies the tool. Transport injectable."""
    hdrs = {"User-Agent": config.USER_AGENT}
    if headers:
        hdrs.update(headers)
    fn = transport if transport is not None else _urllib_get
    return fn(url, timeout, hdrs)


def http_post_json(url: str, payload: dict, timeout: float = 30.0,
                   headers: Optional[dict] = None,
                   transport: Optional[PostTransport] = None) -> Response:
    hdrs = {"User-Agent": config.USER_AGENT}
    if headers:
        hdrs.update(headers)
    if transport is not None:
        return transport(url, payload, timeout, hdrs)
    return _urllib_post_json(url, payload, timeout, hdrs)


def http_put_json(url: str, payload: dict, timeout: float = 30.0,
                  headers: Optional[dict] = None,
                  transport: Optional[PutTransport] = None) -> Response:
    hdrs = {"User-Agent": config.USER_AGENT}
    if headers:
        hdrs.update(headers)
    if transport is not None:
        return transport(url, payload, timeout, hdrs)
    return _urllib_put_json(url, payload, timeout, hdrs)


def http_post_form(url: str, fields: dict, timeout: float = 30.0,
                   headers: Optional[dict] = None,
                   transport: Optional[FormTransport] = None) -> Response:
    """POST application/x-www-form-urlencoded (Gumroad license verify)."""
    hdrs = {"User-Agent": config.USER_AGENT}
    if headers:
        hdrs.update(headers)
    if transport is not None:
        return transport(url, fields, timeout, hdrs)
    return _urllib_post_form(url, fields, timeout, hdrs)


def http_delete(url: str, timeout: float = 30.0,
                headers: Optional[dict] = None,
                transport: Optional[DeleteTransport] = None) -> Response:
    hdrs = {"User-Agent": config.USER_AGENT}
    if headers:
        hdrs.update(headers)
    if transport is not None:
        return transport(url, timeout, hdrs)
    return _urllib_delete(url, timeout, hdrs)
