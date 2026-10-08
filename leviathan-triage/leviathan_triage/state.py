"""Seen-state so alerts fire once. Atomic writes; survives crashes and cron."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .models import Finding

SCHEMA = 1


def finding_key(f: Finding) -> str:
    return f"{f.cve}|{f.asset.identifier}"


class State:
    def __init__(self, path):
        self.path = Path(path)
        self.seen: dict = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            if doc.get("schema") == SCHEMA:
                self.seen = {k: float(v) for k, v in doc.get("seen", {}).items()}
        except (json.JSONDecodeError, ValueError, OSError):
            # corrupt state -> start clean; a re-alert beats a silent blind spot
            self.seen = {}

    def is_new(self, f: Finding) -> bool:
        return finding_key(f) not in self.seen

    def mark(self, findings: list) -> int:
        import time
        now = time.time()
        n = 0
        for f in findings:
            k = finding_key(f)
            if k not in self.seen:
                n += 1
            self.seen[k] = now
        self.save()
        return n

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"schema": SCHEMA, "seen": self.seen}),
                       encoding="utf-8")
        os.replace(tmp, self.path)
