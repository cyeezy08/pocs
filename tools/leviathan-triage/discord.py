"""Discord output layer: embed builders + webhook transport.

Webhook = the 5-minute path (no bot application needed - paste a channel
webhook URL, run on cron). Rich embeds per finding, chunked to Discord's
10-embed limit, with a summary header embed and source provenance.
"""
from __future__ import annotations

from typing import Callable, Optional

from . import config
from .http import Response, http_post_json
from .models import Finding


def _truncate(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


def finding_embed(f: Finding, mark_new: bool = False) -> dict:
    color = config.BAND_COLORS.get(f.band, 0x95A5A6)
    prefix = "[NEW] " if mark_new else ""
    title = f"{prefix}{f.band} · {f.cve} · score {f.score:g}"
    desc = _truncate(f.title or f.asset.identifier, 400)
    reason_lines = "\n".join(r.line() for r in f.reasons[:6])
    if len(f.reasons) > 6:
        reason_lines += f"\n… +{len(f.reasons) - 6} more reasons"
    return {
        "title": title,
        "description": desc,
        "color": color,
        "fields": [
            {"name": "asset", "value": _truncate(f.asset.identifier, 100), "inline": True},
            {"name": "match", "value": _truncate(f.match_confidence, 100), "inline": True},
            {"name": "flags", "value": _truncate(", ".join(f.flags()) or "-", 200), "inline": True},
            {"name": "why", "value": _truncate(reason_lines, 1000)},
        ],
        "footer": {"text": _truncate(
            f"leviathan-triage {config.VERSION} · {config.BAND_MEANING.get(f.band, '')}", 200)},
    }


def summary_embed(findings: list, new_only: bool = False) -> dict:
    counts: dict = {}
    for f in findings:
        counts[f.band] = counts.get(f.band, 0) + 1
    line = " · ".join(f"{b}×{counts[b]}" for b in config.BANDS if b in counts)
    scope = "new findings" if new_only else "findings"
    color = config.BAND_COLORS.get(
        next((b for b in ("P0", "P1", "P2", "P3") if b in counts), None), 0x95A5A6)
    return {
        "title": f"leviathan-triage - {len(findings)} {scope}",
        "description": f"{line or 'nothing'}\n\n{config.DISCLAIMER}",
        "color": color,
        "footer": {"text": f"{config.POSITIONING}"},
    }


def queue_embeds(findings: list, new_only: bool = False,
                 limit: Optional[int] = None) -> list:
    """Summary embed + one embed per finding, chunked to the Discord limit
    (head + body [+ overflow notice] never exceeds `limit`)."""
    limit = limit if limit is not None else config.WEBHOOK_EMBED_LIMIT
    head = summary_embed(findings, new_only=new_only)
    if len(findings) <= limit - 1:
        return [head] + [finding_embed(f) for f in findings]
    body = [finding_embed(f) for f in findings[: limit - 2]]
    body.append({
        "title": f"… and {len(findings) - (limit - 2)} more",
        "description": "run `triage --json` or check the CLI for the full queue",
        "color": 0x95A5A6,
    })
    return [head] + body


def markdown_digest(findings: list) -> str:
    lines = [f"## leviathan-triage - {len(findings)} findings", ""]
    for f in findings:
        lines.append(f"- {f.summary()}")
        for r in f.reasons:
            lines.append(f"  - {r.line()}")
    lines.append("")
    lines.append(f"_{config.DISCLAIMER}_")
    return "\n".join(lines)


def digest_embed(findings: list, buy_url: str = "",
                 limit: int = 5) -> dict:
    """The FREE daily digest - the marketing unit of the feed business.

    One embed: band counts, top P0/P1 lines, and the honest upsell: realtime
    P0/P1 alerts live in the subscriber lane. buy_url empty -> CTA says DM.
    """
    counts: dict = {}
    for f in findings:
        counts[f.band] = counts.get(f.band, 0) + 1
    line = " · ".join(f"{b}×{counts[b]}" for b in config.BANDS if b in counts)
    hot = [f for f in findings if f.band in config.SUBSCRIBER_BANDS]
    lines = [f"**{f.band} {f.score:g}** - {f.summary()}" for f in hot[:limit]]
    if not lines:
        lines = ["no P0/P1 findings today - quiet is not safe, it is quiet"]
    cta = (f"Realtime P0/P1 alerts fire the minute the feeds move - "
           f"that lane is subscriber-only. $5/mo → {buy_url}" if buy_url else
           "Realtime P0/P1 alerts fire the minute the feeds move - "
           "that lane is subscriber-only. Ask the admin for the buy link.")
    return {
        "title": f"free P0 digest - {len(findings)} findings ({line or 'none'})",
        "description": "\n".join(lines)[:4000],
        "color": config.BAND_COLORS.get(
            next((b for b in ("P0", "P1", "P2", "P3") if b in counts), None), 0x95A5A6),
        "fields": [{"name": "go realtime", "value": cta[:1000]}],
        "footer": {"text": _truncate(
            f"free daily digest · leviathan-triage {config.VERSION} · "
            f"{config.DISCLAIMER[:100]}", 200)},
    }


def post_webhook(url: str, embeds: list,
                 transport: Optional[Callable] = None,
                 username: str = "leviathan-triage") -> Response:
    """Post embeds to a Discord webhook. 204 is success."""
    if not embeds:
        raise ValueError("no embeds to post")
    payload = {"username": username, "embeds": embeds}
    r = http_post_json(url, payload, transport=transport)
    if r.status not in (200, 204):
        raise RuntimeError(f"webhook returned HTTP {r.status}: "
                           f"{r.body[:200].decode('utf-8', errors='replace')}")
    return r
