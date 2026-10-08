"""cli: exit-code contract + full dry-run pipeline with stubbed transports."""

from __future__ import annotations

import json

import pytest

from huginn import cli, config


def _gh_api_payload():
    return [
        {"id": "1", "type": "ReleaseEvent", "repo": {"name": "u/Repo"},
         "created_at": "2026-09-19T20:00:00Z",
         "payload": {"release": {"tag_name": "v1.0", "html_url": "https://github.com/u/Repo/r1",
                                 "name": "one point oh"}}},
    ]


def _stub_get(payload):
    def get(url, timeout=20):
        return json.dumps(payload).encode()

    return get


def test_full_pipeline_fetch_draft_post_dryrun(state_dir, monkeypatch, capsys):
    monkeypatch.setenv("HUG_GH_USER", "u")
    monkeypatch.setenv(config.ENV_EVENTS_URL, "https://example.test/events")
    monkeypatch.setattr("huginn.github_feed._get", _stub_get(_gh_api_payload()))

    assert cli.cmd_fetch(type("A", (), {"state_dir": state_dir})()) == config.EXIT_OK
    assert cli.cmd_draft(type("A", (), {"state_dir": state_dir})()) == config.EXIT_OK

    # post without --yes => dry run, exit 0, nothing posted
    rc = cli.cmd_post(type("A", (), {"state_dir": state_dir, "yes": False,
                                     "dry_run": True, "force": False})())
    assert rc == config.EXIT_OK
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert not __import__("huginn.store", fromlist=["x"]).read_jsonl("posted.jsonl", state_dir)


def test_fetch_twice_second_is_nothing(state_dir, monkeypatch):
    monkeypatch.setenv("HUG_GH_USER", "u")
    monkeypatch.setenv(config.ENV_EVENTS_URL, "https://example.test/events")
    monkeypatch.setattr("huginn.github_feed._get", _stub_get(_gh_api_payload()))
    args = type("A", (), {"state_dir": state_dir})()
    assert cli.cmd_fetch(args) == config.EXIT_OK
    assert cli.cmd_fetch(args) == config.EXIT_NOTHING


def test_missing_user_is_error(state_dir, monkeypatch):
    monkeypatch.delenv("HUG_GH_USER", raising=False)
    assert cli.cmd_fetch(type("A", (), {"state_dir": state_dir})()) == config.EXIT_ERROR


def test_interval_guard_blocks_second_post(state_dir, monkeypatch, capsys):
    from huginn import store
    import time

    store.append_jsonl("drafts.jsonl", [
        {"event_id": "e1", "type": "push", "repo": "u/r", "text": "post one"},
        {"event_id": "e2", "type": "push", "repo": "u/r", "text": "post two"},
    ], state_dir)
    store.append_one("posted.jsonl", {"event_id": "e0", "ts": int(time.time())}, state_dir)
    args = type("A", (), {"state_dir": state_dir, "yes": True, "dry_run": False, "force": False})()
    assert cli.cmd_post(args) == config.EXIT_NOTHING
    assert "too soon" in capsys.readouterr().out

    args_force = type("A", (), {"state_dir": state_dir, "yes": True, "dry_run": False, "force": True})()
    # with force, it would attempt a real post -> stub the api
    monkeypatch.setattr("huginn.xapi.post_tweet", lambda text, post=None: {"data": {"id": "9", "text": text}})
    assert cli.cmd_post(args_force) == config.EXIT_OK
    posted = store.read_jsonl("posted.jsonl", state_dir)
    assert posted[-1]["event_id"] == "e1" and posted[-1]["tweet_id"] == "9"


def test_status_reports_counts(state_dir, capsys):
    from huginn import store

    store.append_jsonl("events.jsonl", [{"event_id": "a"}], state_dir)
    assert cli.cmd_status(type("A", (), {"state_dir": state_dir})()) == config.EXIT_OK
    assert "events: 1" in capsys.readouterr().out


def test_main_wires_exit_codes(state_dir, monkeypatch):
    monkeypatch.delenv("HUG_GH_USER", raising=False)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--state-dir", state_dir, "fetch"])
    assert exc.value.code == config.EXIT_ERROR
