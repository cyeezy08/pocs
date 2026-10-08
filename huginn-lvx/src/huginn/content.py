"""Draft engine: event -> 280-safe post, deduped against the posted ledger.

Length is X-weighted, not character count:
- URLs count as a fixed 23 (t.co rewrite)
- CJK / Hangul / emoji code points count as 2
- everything else counts as 1
"""

from __future__ import annotations

import re

from . import config

_URL_RE = re.compile(r"https?://\S+")

# X weighted-2 ranges (CJK ideographs, Hiragana/Katakana, Hangul, emoji blocks).
_WIDE_RANGES = (
    (0x1100, 0x115F), (0x2E80, 0xA4CF), (0xAC00, 0xD7A3), (0xF900, 0xFAFF),
    (0xFE30, 0xFE4F), (0xFF00, 0xFF60), (0xFFE0, 0xFFE6),
    (0x1F300, 0x1F64F), (0x1F680, 0x1F6FF), (0x1F900, 0x1F9FF),
    (0x1FA70, 0x1FAFF), (0x2000, 0x206F),  # general punctuation varies; treat as 1 - kept out
)
# NOTE: 0x2000-0x206F excluded - do NOT double-count punctuation.
_WIDE_RANGES = tuple(r for r in _WIDE_RANGES if r[0] != 0x2000)


def x_length(text: str) -> int:
    """Weighted X length of text with URLs collapsed to t.co weight."""
    total = 0
    pos = 0
    for match in _URL_RE.finditer(text):
        total += _plain_length(text[pos:match.start()]) + config.URL_WEIGHT
        pos = match.end()
    total += _plain_length(text[pos:])
    return total


def _plain_length(text: str) -> int:
    total = 0
    for ch in text:
        cp = ord(ch)
        if any(lo <= cp <= hi for lo, hi in _WIDE_RANGES):
            total += 2
        else:
            total += 1
    return total


def render(event: dict) -> str:
    """Render a template for an event, clamped to the weighted 280 limit."""
    template = config.TEMPLATES.get(event["type"])
    if template is None:
        raise ValueError(f"unknown event type: {event['type']!r}")
    text = template.format(
        repo=event.get("repo", ""),
        tag=event.get("tag") or "v-latest",
        summary=event.get("summary") or config.DEFAULT_SUMMARY,
        n=event.get("n_commits") or 1,
        url=event.get("url", ""),
    )
    return clamp(text)


def clamp(text: str) -> str:
    """Trim to the weighted limit: repeatedly shorten the longest prose line,
    keep the URL line (it counts a fixed 23) and hashtag line intact."""
    if x_length(text) <= config.MAX_POST_CHARS:
        return text
    lines = [ln for ln in text.split("\n")]
    for _ in range(64):
        if x_length("\n".join(lines)) <= config.MAX_POST_CHARS:
            return "\n".join(lines)
        # longest line that is neither a URL line nor a pure-hashtag line
        idx, best = -1, -1
        for i, ln in enumerate(lines):
            if _URL_RE.search(ln) or (ln.startswith("#") and " " not in ln):
                continue
            w = x_length(ln)
            if w > best:
                idx, best = i, w
        if idx == -1:
            break
        ln = lines[idx]
        # cut 25% of the line (min 8 chars), keep ellipsis tidy
        cut = max(8, best // 4)
        ln = ln[: max(0, best - cut)].rstrip()
        if not ln.endswith("\u2026"):
            ln = (ln[: max(0, len(ln) - 1)] if len(ln) > 1 else "") .rstrip()
            ln = (ln + "\u2026") if ln else "\u2026"
        lines[idx] = ln
    return _hard_cut(lines)


def _hard_cut(lines: list[str]) -> str:
    out = []
    used = 0
    for ln in lines:
        w = x_length(ln)
        if used + w > config.MAX_POST_CHARS:
            break
        out.append(ln)
        used += w + 1
    return "\n".join(out) if out else lines[0][: config.MAX_POST_CHARS]


def draft_from_events(events: list[dict], posted: set[str], drafted: set[str]) -> list[dict]:
    """Fresh, sorted, deduped drafts - newest first, capped per run."""
    rows = []
    seen = set()
    for ev in sorted(events, key=lambda e: e.get("created_at", ""), reverse=True):
        eid = ev.get("event_id", "")
        if not eid or eid in posted or eid in drafted or eid in seen:
            continue
        seen.add(eid)
        try:
            text = render(ev)
        except ValueError:
            continue
        rows.append({"event_id": eid, "type": ev["type"], "repo": ev["repo"], "text": text})
        if len(rows) >= config.MAX_DRAFTS_PER_RUN:
            break
    return rows
