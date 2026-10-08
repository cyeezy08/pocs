"""store: atomic jsonl state under a temp state dir."""

from __future__ import annotations

import json

from huginn import store


def test_roundtrip(state_dir):
    store.append_jsonl("events.jsonl", [{"event_id": "a", "repo": "r"}], state_dir)
    store.append_jsonl("events.jsonl", [{"event_id": "b", "repo": "r2"}], state_dir)
    rows = store.read_jsonl("events.jsonl", state_dir)
    assert [r["event_id"] for r in rows] == ["a", "b"]  # append preserves history


def test_partial_line_skipped_not_crash(state_dir):
    path = f"{state_dir}/events.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"event_id": "good"}) + "\n")
        fh.write('{"event_id": "trunc')  # crashed mid-write
    rows = store.read_jsonl("events.jsonl", state_dir)
    assert [r["event_id"] for r in rows] == ["good"]


def test_posted_ids_and_membership(state_dir):
    store.append_one("posted.jsonl", {"event_id": "e1", "ts": 1}, state_dir)
    store.append_one("posted.jsonl", {"event_id": "e2", "ts": 2}, state_dir)
    assert store.posted_ids(state_dir) == {"e1", "e2"}
    assert store.is_posted("e1", state_dir)
    assert not store.is_posted("e9", state_dir)


def test_append_one_hot_path_appends(state_dir):
    store.append_one("posted.jsonl", {"event_id": "a"}, state_dir)
    store.append_one("posted.jsonl", {"event_id": "b"}, state_dir)
    assert len(store.read_jsonl("posted.jsonl", state_dir)) == 2


def test_empty_append_is_noop(state_dir):
    store.append_jsonl("events.jsonl", [], state_dir)
    assert store.read_jsonl("events.jsonl", state_dir) == []
