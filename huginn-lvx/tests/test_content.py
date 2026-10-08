"""content: weighted lengths, clamping, dedupe, ordering."""

from __future__ import annotations

from huginn import config, content


def test_ascii_length_is_one_per_char():
    assert content.x_length("hello world") == 11


def test_url_counts_fixed_23():
    assert content.x_length("https://github.com/cyeezy08/HostageLVX") == config.URL_WEIGHT
    assert content.x_length("see https://x.com now") == 4 + config.URL_WEIGHT + 4


def test_cjk_and_emoji_count_double():
    assert content._plain_length("猶") == 2
    assert content._plain_length("hello") == 5
    assert content._plain_length("\U0001F6A8") == 2


def test_render_release_under_limit():
    ev = {
        "type": "release", "repo": "cyeezy08/HostageLVX", "tag": "v0.3.0",
        "summary": "brutalist takeover engine", "n_commits": 0,
        "url": "https://github.com/cyeezy08/HostageLVX/releases/v0.3.0",
    }
    text = content.render(ev)
    assert content.x_length(text) <= config.MAX_POST_CHARS
    assert "v0.3.0" in text and "HostageLVX" in text
    assert "#infosec" in text


def test_clamp_never_exceeds_280_even_for_monster_events():
    ev = {
        "type": "release", "repo": "cyeezy08/some-repo", "tag": "v9.9.9",
        "summary": "word " * 80, "n_commits": 0,
        "url": "https://github.com/cyeezy08/some-repo/releases/v9.9.9",
    }
    text = content.render(ev)
    assert content.x_length(text) <= config.MAX_POST_CHARS
    assert "some-repo" in text  # repo name survives
    assert "github.com" in text or "t.co" in text  # URL survives


def test_clamp_preserves_hashtags_when_possible():
    text = "\n".join(["x" * 300, "https://github.com/a/b", "#infosec #bugbounty"])
    out = content.clamp(text)
    assert content.x_length(out) <= config.MAX_POST_CHARS
    assert "#bugbounty" in out or "#infosec" in out


def test_dedupe_and_cap():
    events = [
        {"event_id": f"e{i}", "type": "push", "repo": f"u/r{i}", "summary": "s",
         "n_commits": 1, "url": "https://github.com/u/r", "tag": "",
         "created_at": f"2026-09-1{i}T00:00:00Z"}
        for i in range(10)
    ]
    rows = content.draft_from_events(events, posted={"e0"}, drafted={"e1"}, )
    assert len(rows) == config.MAX_DRAFTS_PER_RUN  # 8 fresh, capped at 5
    ids = [r["event_id"] for r in rows]
    assert "e0" not in ids and "e1" not in ids
    assert len(ids) == len(set(ids))


def test_drafted_already_in_queue_not_redrafted():
    events = [{"event_id": "e1", "type": "push", "repo": "u/r", "summary": "s",
               "n_commits": 1, "url": "https://github.com/u/r", "tag": "",
               "created_at": "2026-09-10T00:00:00Z"}]
    assert content.draft_from_events(events, set(), {"e1"}) == []


def test_unknown_event_type_skipped_not_crash():
    events = [{"event_id": "e1", "type": "gods_know", "repo": "u/r", "summary": "s",
               "n_commits": 0, "url": "", "tag": "", "created_at": "z"}]
    assert content.draft_from_events(events, set(), set()) == []


def test_newest_first_ordering():
    events = [
        {"event_id": "old", "type": "push", "repo": "u/r", "summary": "s", "n_commits": 1,
         "url": "https://github.com/u/r", "tag": "", "created_at": "2026-01-01T00:00:00Z"},
        {"event_id": "new", "type": "push", "repo": "u/r", "summary": "s", "n_commits": 1,
         "url": "https://github.com/u/r", "tag": "", "created_at": "2026-09-19T00:00:00Z"},
    ]
    rows = content.draft_from_events(events, set(), set())
    assert [r["event_id"] for r in rows] == ["new", "old"]
