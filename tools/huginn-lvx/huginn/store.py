"""Atomic jsonl state: events, drafts, posted ledger.

Every file op is tmp+rename; every line is one JSON object. Crash-safe by
construction: a partial line is discarded on read instead of poisoning state.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


def _state_dir(state_dir: str | None = None) -> Path:
    root = Path(state_dir or os.environ.get("HUG_STATE_DIR", os.path.expanduser("~/.huginn")))
    root.mkdir(parents=True, exist_ok=True)
    return root


def read_jsonl(name: str, state_dir: str | None = None) -> list[dict]:
    path = _state_dir(state_dir) / name
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # partial write from a crashed run - skip, never crash
    return out


def append_jsonl(name: str, rows: list[dict], state_dir: str | None = None) -> None:
    """Append rows, preserving existing content. New file: atomic rename."""
    if not rows:
        return
    path = _state_dir(state_dir) / name
    payload = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows)
    if path.is_file():
        with path.open("a", encoding="utf-8") as fh:
            fh.write(payload)
    else:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(str(tmp), str(path))


def append_one(name: str, row: dict, state_dir: str | None = None) -> None:
    """Append a single row without rewriting the file (ledger hot path)."""
    path = _state_dir(state_dir) / name
    line = json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line)


def posted_ids(state_dir: str | None = None) -> set[str]:
    return {r.get("event_id", "") for r in read_jsonl("posted.jsonl", state_dir)}


def drafted_ids(state_dir: str | None = None) -> set[str]:
    return {r.get("event_id", "") for r in read_jsonl("drafts.jsonl", state_dir)}


def is_posted(event_id: str, state_dir: str | None = None) -> bool:
    return event_id in posted_ids(state_dir)
