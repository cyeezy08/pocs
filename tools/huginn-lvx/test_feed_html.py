"""HTML fallback: API rate-limited -> public profile page scraping."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from huginn import github_feed


def _api_down(url, timeout=20):
    raise OSError("HTTP 403 rate limit")


PAGE_TEMPLATE = """
<li class="x" itemprop="owns" itemscope>
  <a href="/{user}/{repo}" itemprop="name codeRepository">{repo}</a>
  <p itemprop="description">{desc}</p>
  <span itemprop="programmingLanguage">Go</span>
  <relative-time datetime="{dt}"></relative-time>
</li>
"""


def _page(user, repos):
    return "".join(PAGE_TEMPLATE.format(user=user, **r) for r in repos).encode()


def _dt(days_ago: float) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_api_failure_falls_back_to_html():
    html = _page(
        "cyeezy08",
        [
            {"repo": "HostageLVX", "desc": "dangling-DNS &amp; takeover engine", "dt": _dt(0.1)},
            {"repo": "FenrirLVX", "desc": "wordpress recon cli", "dt": _dt(0.2)},
        ],
    )

    def get_html(url, timeout=20):
        return html

    events = github_feed.fetch_events("cyeezy08", get_json=_api_down, get_html=get_html)
    assert [e["repo"] for e in events] == ["cyeezy08/HostageLVX", "cyeezy08/FenrirLVX"]
    assert events[0]["type"] == "pushhtml"
    assert "&amp;" not in events[0]["summary"]  # entities unescaped
    assert "takeover" in events[0]["summary"]


def test_stale_repos_filtered_by_window():
    html = _page(
        "u",
        [
            {"repo": "fresh", "desc": "new", "dt": _dt(1)},
            {"repo": "ancient", "desc": "old", "dt": _dt(30)},
        ],
    )
    events = github_feed._events_from_html("u", lambda url, timeout=20: html)
    assert [e["repo"] for e in events] == ["u/fresh"]


def test_event_ids_stable_across_polls():
    html = _page("u", [{"repo": "r", "desc": "d", "dt": _dt(0.5)}])
    e1 = github_feed._events_from_html("u", lambda url, timeout=20: html)
    e2 = github_feed._events_from_html("u", lambda url, timeout=20: html)
    assert e1[0]["event_id"] == e2[0]["event_id"]
    assert e1[0]["event_id"].startswith("html:u/r:2026-")


def test_html_unreachable_raises_feed_error():
    with pytest.raises(github_feed.FeedError):
        github_feed._events_from_html("u", _api_down)


def test_malformed_dates_skipped():
    html = _page("u", [{"repo": "weird", "desc": "d", "dt": "not-a-date"}])
    assert github_feed._events_from_html("u", lambda url, timeout=20: html) == []


def test_both_paths_down_raises():
    def both_down(url, timeout=20):
        raise OSError("nope")

    with pytest.raises(github_feed.FeedError):
        github_feed.fetch_events("u", get_json=both_down, get_html=both_down)


def test_api_still_wins_when_healthy():
    payload = json.dumps(
        [{"id": "1", "type": "PushEvent", "repo": {"name": "u/r", },
          "created_at": "2026-09-19T00:00:00Z",
          "payload": {"size": 1, "commits": [{"message": "m"}]}}]
    ).encode()
    events = github_feed.fetch_events(
        "u", get_json=lambda url, timeout=20: payload, get_html=_api_down
    )
    assert events[0]["type"] == "push"
