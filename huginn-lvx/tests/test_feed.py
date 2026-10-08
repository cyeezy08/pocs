"""github_feed: normalize GH events with a stubbed transport (no network)."""

from __future__ import annotations

import json

import pytest

from huginn import github_feed


def _stub(payload, fail=False):
    def get(url, timeout=20):
        if fail:
            raise OSError("conn refused")
        return json.dumps(payload).encode()

    return get


RAW = [
    {
        "id": "1",
        "type": "ReleaseEvent",
        "repo": {"name": "cyeezy08/HostageLVX"},
        "created_at": "2026-09-19T20:00:00Z",
        "payload": {
            "release": {
                "tag_name": "v0.3.0",
                "html_url": "https://github.com/cyeezy08/HostageLVX/releases/v0.3.0",
                "name": "v0.3.0 - brutalist takeover engine",
            }
        },
    },
    {
        "id": "2",
        "type": "PushEvent",
        "repo": {"name": "cyeezy08/FenrirLVX"},
        "created_at": "2026-09-19T20:17:00Z",
        "payload": {"size": 3, "commits": [{"message": "fix: honeypot filter false positives"}]},
    },
    {
        "id": "3",
        "type": "CreateEvent",
        "repo": {"name": "cyeezy08/BrandNewTool"},
        "created_at": "2026-09-19T21:00:00Z",
        "payload": {"description": "something that kicks cash"},
    },
    {"id": "4", "type": "WatchEvent", "repo": {"name": "cyeezy08/HostageLVX"}, "payload": {}},
    {"id": "5", "type": "PushEvent", "repo": {}, "payload": {}},  # no repo - skip
]


def test_normalizes_only_interesting_events():
    events = github_feed.fetch_events("cyeezy08", get_json=_stub(RAW))
    kinds = [e["type"] for e in events]
    assert kinds == ["release", "push", "newrepo"]
    assert all(e["event_id"] for e in events)


def test_release_event_fields():
    events = github_feed.fetch_events("cyeezy08", get_json=_stub(RAW))
    rel = next(e for e in events if e["type"] == "release")
    assert rel["repo"] == "cyeezy08/HostageLVX"
    assert rel["tag"] == "v0.3.0"
    assert rel["url"].endswith("/releases/v0.3.0")
    assert "brutalist" in rel["summary"]


def test_push_event_counts_and_summary():
    events = github_feed.fetch_events("cyeezy08", get_json=_stub(RAW))
    push = next(e for e in events if e["type"] == "push")
    assert push["n_commits"] == 3
    assert push["summary"].startswith("fix: honeypot")


def test_network_failure_both_paths_raises_feed_error():
    with pytest.raises(github_feed.FeedError):
        github_feed.fetch_events(
            "cyeezy08", get_json=_stub(None, fail=True), get_html=_stub(None, fail=True)
        )


def test_bad_payload_both_paths_raises_feed_error():
    def get(url, timeout=20):
        return json.dumps({"message": "API rate limit exceeded"}).encode()

    with pytest.raises(github_feed.FeedError):
        github_feed.fetch_events("cyeezy08", get_json=get, get_html=get)


def test_summary_clamped_with_ellipsis():
    long_desc = "x" * 500
    raw = [{"id": "9", "type": "CreateEvent", "repo": {"name": "u/r"}, "payload": {"description": long_desc}}]
    events = github_feed.fetch_events("u", get_json=_stub(raw))
    assert len(events[0]["summary"]) <= 120
    assert events[0]["summary"].endswith("\u2026")
