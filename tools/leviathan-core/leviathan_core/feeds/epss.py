"""FIRST EPSS bulk scores (daily CSV, gzipped) -> {cve: probability}."""
from __future__ import annotations

import csv
import gzip
import io
from pathlib import Path

import requests

from .. import config


def sync(cache_dir: Path) -> dict[str, float]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "epss.csv"
    if cache_file.exists():
        return _parse(cache_file.read_text())
    r = requests.get(config.FEEDS["epss"], timeout=120,
                     headers={"User-Agent": config.TOOL})
    r.raise_for_status()
    text = gzip.decompress(r.content).decode("utf-8", errors="replace")
    cache_file.write_text(text)
    return _parse(text)


def _parse(text: str) -> dict[str, float]:
    out: dict[str, float] = {}
    lines = text.splitlines()
    # line 0 is a model-metadata comment; line 1 is the header (cve,epss,percentile)
    header_idx = next((i for i, l in enumerate(lines) if l.startswith("cve,")), None)
    if header_idx is None:
        return out
    reader = csv.DictReader(io.StringIO("\n".join(lines[header_idx:])))
    for row in reader:
        cve = (row.get("cve") or "").strip()
        score = (row.get("epss") or "").strip()
        if cve.startswith("CVE-") and score:
            try:
                out[cve] = float(score)
            except ValueError:
                continue
    return out


def model_date(cache_dir: Path) -> str:
    f = cache_dir / "epss.csv"
    if f.exists():
        first = f.read_text().splitlines()[0] if f.read_text() else ""
        return first.lstrip("# ").strip() or "unknown"
    return "not synced"
