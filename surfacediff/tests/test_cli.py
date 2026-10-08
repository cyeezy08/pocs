import json

import pytest

from surfacediff.cli import main

HTTPX_A = '{"url":"https://a.example.com","status_code":200,"title":"Home"}'
HTTPX_B_CHANGED = '{"url":"https://a.example.com","status_code":403,"title":"Home"}'
HTTPX_C_NEW = '{"url":"https://c.example.com","status_code":200,"title":"New"}'


def test_snap_diff_cycle_exit_codes(tmp_path, monkeypatch, capsys):
    # first snapshot (baseline)
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: HTTPX_A)})())
    rc = main(["--dir", str(tmp_path), "--silent", "snap", "-l", "web"])
    assert rc == 0
    capsys.readouterr()

    # diff on identical baseline-only history -> clean (no changes path)
    rc = main(["--dir", str(tmp_path), "--silent", "diff", "-l", "web"])
    assert rc == 0  # first snapshot baseline note -> OK

    # second snapshot with changes
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: HTTPX_B_CHANGED + "\n" + HTTPX_C_NEW)})())
    rc = main(["--dir", str(tmp_path), "--silent", "snap", "-l", "web"])
    assert rc == 0

    # diff now reports changes -> exit 1
    rc = main(["--dir", str(tmp_path), "diff", "-l", "web", "--no-color"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "url|https://c.example.com" in out
    assert "status_code: 200 -> 403" in out


def test_diff_json_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: HTTPX_A)})())
    main(["--dir", str(tmp_path), "--silent", "snap", "-l", "web"])
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: HTTPX_B_CHANGED)})())
    main(["--dir", str(tmp_path), "--silent", "snap", "-l", "web"])
    rc = main(["--dir", str(tmp_path), "--silent", "diff", "-l", "web", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert data["counts"]["changed"] == 1
    assert data["from"] != data["to"]


def test_show_lists_snapshots(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: HTTPX_A)})())
    main(["--dir", str(tmp_path), "--silent", "snap", "-l", "web", "--tag", "env=prod", "--source", "httpx"])
    rc = main(["--dir", str(tmp_path), "show", "-l", "web"])
    out = capsys.readouterr().out
    assert rc == 0 and ".jsonl" in out and "env=prod" in out and "httpx" in out


def test_empty_input_errors(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: "")})())
    rc = main(["--dir", str(tmp_path), "--silent", "snap", "-l", "web"])
    assert rc == 2


def test_bad_tag_errors(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: "x.com")})())
    rc = main(["--dir", str(tmp_path), "--silent", "snap", "-l", "web", "--tag", "noequalsign"])
    assert rc == 2
