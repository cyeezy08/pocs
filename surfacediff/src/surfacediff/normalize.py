"""Adapters: turn any pipeline tool output into normalized asset records.

Supported inputs (auto-detected per line):
  - httpx -json lines    -> kind=url   (status/title/tech/... kept as attrs)
  - naabu  -json lines   -> kind=port
  - plain domains/IPs    -> kind=host  (subfinder, dnsx -a, amass, ...)
  - plain URLs           -> kind=url

Records:
  {"key": "url|https://example.com", "kind": "url",
   "attrs": {...}, "hash": "<sha256 of attrs>"}

The hash is the change-detector: same key + different hash = changed asset.
"""
from __future__ import annotations

import hashlib
import json
import ipaddress
from urllib.parse import urlsplit

from . import config


class Asset:
    __slots__ = ("key", "kind", "attrs")

    def __init__(self, kind: str, identity: str, attrs: dict | None = None):
        self.kind = kind
        self.key = f"{kind}|{identity}"
        self.attrs = attrs or {}

    def hash(self) -> str:
        blob = json.dumps(self.attrs, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def to_record(self) -> dict:
        return {"key": self.key, "kind": self.kind, "attrs": self.attrs, "hash": self.hash()}


def _clean_url(url: str) -> str:
    """Canonical URL key: lowercase scheme/host, drop default ports, drop fragment."""
    try:
        p = urlsplit(url.strip())
        if not p.netloc:
            return ""
        host = (p.hostname or "").lower()
        scheme = (p.scheme or "http").lower()
        port = p.port
        default = {"http": 80, "https": 443}.get(scheme)
        netloc = host if port in (None, default) else f"{host}:{port}"
        path = p.path.rstrip("/") or ""
        query = f"?{p.query}" if p.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except ValueError:
        return ""


def _looks_like_host(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        pass
    parts = s.lower().rstrip(".").split(".")
    return (
        len(parts) >= 2
        and all(p and all(c.isalnum() or c == "-" for c in p) for p in parts)
        and not parts[-1].startswith("-")
    )


def _from_httpx(doc: dict) -> Asset | None:
    url = doc.get("url") or doc.get("input")
    if not url:
        return None
    canonical = _clean_url(str(url))
    if not canonical:
        return None
    attrs = {k: doc[k] for k in config.HTTPX_ATTRS if doc.get(k) not in (None, "", [])}
    return Asset("url", canonical, attrs)


def _from_naabu(doc: dict) -> Asset | None:
    host = doc.get("host") or doc.get("ip")
    port = doc.get("port")
    if not host or port is None:
        return None
    proto = doc.get("protocol", "tcp")
    return Asset("port", f"{host}:{proto}/{port}",
                 {k: doc[k] for k in config.NAABU_ATTRS if doc.get(k) not in (None, "")})


def _from_json(doc: dict) -> Asset | None:
    if "url" in doc or "status_code" in doc and ("host" in doc or "input" in doc):
        a = _from_httpx(doc)
        if a:
            return a
    if "port" in doc and (doc.get("host") or doc.get("ip")):
        return _from_naabu(doc)
    return None


def parse_line(line: str) -> tuple[Asset | None, str | None]:
    """Parse one input line -> (Asset, None) or (None, warning)."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None, None
    if s.startswith("{"):
        try:
            doc = json.loads(s)
        except json.JSONDecodeError:
            return None, f"skipped malformed JSON line: {s[:60]}"
        a = _from_json(doc if isinstance(doc, dict) else {})
        if a is None:
            return None, f"skipped unrecognized JSON shape: {s[:60]}"
        return a, None
    if "://" in s:
        canonical = _clean_url(s)
        if not canonical:
            return None, f"skipped unparsable URL: {s[:60]}"
        return Asset("url", canonical), None
    host = s.lower().rstrip(".")
    if _looks_like_host(host):
        return Asset("host", host), None
    return None, f"skipped unrecognized line: {s[:60]}"


def parse_stream(text: str) -> tuple[list[Asset], list[str]]:
    """Parse a whole input stream -> (assets, warnings). Dedupes by key,
    merging attrs (later lines enrich earlier ones)."""
    assets: dict[str, Asset] = {}
    warnings: list[str] = []
    for line in text.splitlines():
        a, warn = parse_line(line)
        if warn:
            warnings.append(warn)
            continue
        if a is None:
            continue
        existing = assets.get(a.key)
        if existing is None:
            assets[a.key] = a
        else:
            merged = {**existing.attrs, **{k: v for k, v in a.attrs.items() if v is not None}}
            existing.attrs = merged
    return list(assets.values()), warnings
