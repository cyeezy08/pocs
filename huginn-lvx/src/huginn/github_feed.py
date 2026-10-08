"""GitHub public events feed - what did the user ship lately?

Uses the public /users/{user}/events/public API (60 req/hr unauthenticated -
fine for hourly polling). Transport is injectable for tests; zero deps.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from . import config

API_TEMPLATE = "https://api.github.com/users/{user}/events/public?per_page=30"

# event types we turn into posts, mapped to template keys
INTERESTING = {
    "ReleaseEvent": "release",
    "CreateEvent": "newrepo",
    "PushEvent": "push",
    "PublicEvent": "public",
}


def _get(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "huginn-lvx",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _get_html(url: str, timeout: int = 20) -> bytes:
    """HTML fetch needs a browser-ish UA - GitHub 403s the default urllib one."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "text/html",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_events(user: str, get_json=None, get_html=None) -> list[dict]:
    """Normalized events, newest first. API first; public-HTML fallback when
    the API rate-limits (shared IPs burn the 60/hr fast)."""
    try:
        return _events_from_api(user, get_json or _get)
    except FeedError:
        return _events_from_html(user, get_html or _get_html)


def _events_from_api(user: str, get) -> list[dict]:
    """Normalized shape: {"event_id", "type" (release|newrepo|push|public),
    "repo", "url", "tag", "summary", "n_commits", "created_at"}."""
    url = os.environ.get(config.ENV_EVENTS_URL) or API_TEMPLATE.format(user=user)
    try:
        payload = json.loads(get(url).decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        raise FeedError(f"github feed unreachable: {e}") from e
    if not isinstance(payload, list):
        raise FeedError(f"github feed returned unexpected payload: {str(payload)[:120]}")

    events: list[dict] = []
    for raw in payload:
        etype = raw.get("type")
        kind = INTERESTING.get(etype)
        if not kind:
            continue
        repo = (raw.get("repo") or {}).get("name", "")
        if not repo:
            continue
        ev = {
            "event_id": str(raw.get("id", "")),
            "type": kind,
            "repo": repo,
            "url": f"https://github.com/{repo}",
            "tag": "",
            "summary": config.DEFAULT_SUMMARY,
            "n_commits": 0,
            "created_at": raw.get("created_at", ""),
        }
        payload_body = raw.get("payload") or {}
        if kind == "release":
            release = payload_body.get("release") or {}
            ev["tag"] = release.get("tag_name", "")
            ev["url"] = release.get("html_url") or ev["url"]
            body = (release.get("name") or release.get("body") or "").strip()
            ev["summary"] = _summary(body)
        elif kind == "push":
            commits = payload_body.get("commits") or []
            size = payload_body.get("size") or len(commits) or 1
            ev["n_commits"] = size
            first = (commits[0].get("message", "").splitlines() or [""])[0] if commits else ""
            ev["summary"] = _summary(first or config.DEFAULT_SUMMARY)
        elif kind == "newrepo":
            desc = (payload_body.get("description") or "").strip()
            ev["summary"] = _summary(desc or config.DEFAULT_SUMMARY)
        events.append(ev)
    return events


def _summary(text: str, limit: int = 120) -> str:
    text = " ".join(str(text).split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "\u2026"
    return text or config.DEFAULT_SUMMARY


def _events_from_html(user: str, get_html) -> list[dict]:
    """Public profile fallback: repo list blocks -> 'repo updated' events.

    Only repos pushed within HTML_FALLBACK_DAYS count as news; event ids are
    stable (html:{repo}:{pushed_at}) so repeated polls dedupe naturally.
    """
    import html as html_mod
    import re
    from datetime import datetime, timedelta, timezone

    url = f"https://github.com/{user}?tab=repositories"
    try:
        page = get_html(url).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise FeedError(f"github profile page unreachable: {e}") from e

    blocks = re.split(r'<li[^>]*itemprop="owns"', page)
    # A JSON body here means the endpoint got hijacked by a proxy/rate-limiter
    # (or the API URL env var points at the JSON API) - never treat as "0 repos".
    if not blocks[1:] and page.lstrip()[:1] in "{[":
        raise FeedError("profile page returned JSON, not HTML (proxy or wrong URL?)")
    cutoff = datetime.now(timezone.utc) - timedelta(days=HTML_FALLBACK_DAYS)
    events: list[dict] = []
    for block in blocks[1:]:
        m_name = re.search(rf'href="/{re.escape(user)}/([A-Za-z0-9_.-]+)"', block)
        if not m_name:
            continue
        repo_full = f"{user}/{m_name.group(1)}"
        m_dt = re.search(r'datetime="([^"]+)"', block)
        m_desc = re.search(r'itemprop="description">\s*([^<]*)', block)
        desc = html_mod.unescape(m_desc.group(1)).strip() if m_desc else ""
        pushed = m_dt.group(1) if m_dt else ""
        try:
            pushed_dt = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
        except ValueError:
            continue
        if pushed_dt < cutoff:
            continue
        events.append(
            {
                "event_id": f"html:{repo_full}:{pushed}",
                "type": "pushhtml",
                "repo": repo_full,
                "url": f"https://github.com/{repo_full}",
                "tag": "",
                "summary": _summary(desc),
                "n_commits": 0,
                "created_at": pushed,
            }
        )
    events.sort(key=lambda e: e["created_at"], reverse=True)
    return events


HTML_FALLBACK_DAYS = 7


class FeedError(RuntimeError):
    pass

