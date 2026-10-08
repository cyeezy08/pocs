"""Snapshot store: immutable JSONL files + a `current` pointer.

Layout (git-friendly - commit the dir for free versioned surface history):
  <dir>/<label>/<YYYYMMDDTHHMMSSZ>.jsonl   (records, sorted by key)
  <dir>/<label>/current                    (filename of newest snapshot)

The first line of every snapshot is a meta record (_meta key) - tool version,
UTC timestamp, tags - so a snapshot is self-describing.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from . import config
from .normalize import Asset


def store_dir(base: str | None, label: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", label or ""):
        raise ValueError(f"invalid label: {label!r} (letters, digits, dot, dash, underscore)")
    base = base or os.environ.get(config.ENV_DIR) or config.DEFAULT_DIR
    p = Path(base) / label
    p.mkdir(parents=True, exist_ok=True)
    return p


def snap(base: str | None, label: str, assets: list[Asset],
         tags: dict | None = None) -> Path:
    """Write a new immutable snapshot; update the pointer. Returns the path."""
    d = store_dir(base, label)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = d / f"{ts}.jsonl"
    n = 0
    while path.exists():  # same-second collision: never overwrite
        n += 1
        path = d / f"{ts}_{n}.jsonl"
    meta = {
        config.META_KEY: {
            "tool": config.TOOL, "version": config.VERSION,
            "format": config.SNAPSHOT_FORMAT,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tags": tags or {},
        }
    }
    records = [meta] + [a.to_record() for a in sorted(assets, key=lambda x: x.key)]
    path.write_text("\n".join(json.dumps(r, separators=(",", ":")) for r in records) + "\n")
    (d / config.POINTER_NAME).write_text(path.name)
    return path


def list_snapshots(base: str | None, label: str) -> list[str]:
    d = store_dir(base, label)
    return sorted(p.name for p in d.glob("*.jsonl"))


def load(base: str | None, label: str, ref: str = "current") -> dict:
    """Load a snapshot by ref: 'current', a filename, or a timestamp prefix.
    Returns {"meta": {...}, "records": {key: record}, "file": name}."""
    d = store_dir(base, label)
    if ref in ("", "current"):
        name = (d / config.POINTER_NAME).read_text().strip()
    else:
        name = ref
        if not name.endswith(".jsonl"):
            matches = [f for f in list_snapshots(base, label) if f.startswith(ref)]
            if not matches:
                raise FileNotFoundError(f"no snapshot matching {ref!r} for label {label!r}")
            name = matches[-1]
    path = d / name
    if not path.exists():
        raise FileNotFoundError(f"snapshot not found: {path}")
    meta, records = {}, {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        doc = json.loads(line)
        if config.META_KEY in doc:
            meta = doc[config.META_KEY]
        else:
            records[doc["key"]] = doc
    return {"meta": meta, "records": records, "file": name}


def latest_pair(base: str | None, label: str, from_ref: str | None) -> tuple[dict, dict]:
    """Resolve (old, new) for diffing: --from given -> that vs current;
    otherwise the two most recent snapshots."""
    snaps = list_snapshots(base, label)
    if len(snaps) < 1:
        raise FileNotFoundError(f"no snapshots for label {label!r} - run `surfacediff snap` first")
    if len(snaps) == 1:
        empty = {"meta": {}, "records": {}, "file": "(none)"}
        return empty, load(base, label, snaps[-1])
    if from_ref:
        return load(base, label, from_ref), load(base, label, "current")
    return load(base, label, snaps[-2]), load(base, label, snaps[-1])
