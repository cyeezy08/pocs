"""Report generation - JSON + Markdown. Counts derived from data, never typed."""
from __future__ import annotations

import json
from pathlib import Path

from . import config
from .models import Finding


def write_reports(findings: list[Finding], out_dir: Path, meta: dict) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jpath = out_dir / "findings.json"
    mpath = out_dir / "REPORT.md"

    jpath.write_text(json.dumps(
        {
            "tool": config.TOOL,
            "version": config.VERSION,
            "generated_from": meta,
            "disclaimer": config.DISCLAIMER,
            "counts": {
                "findings": len(findings),
                "in_kev": sum(1 for f in findings if f.in_kev),
                "ransomware_associated": sum(1 for f in findings if f.kev_known_ransomware),
                "with_public_poc": sum(1 for f in findings if f.has_poc_ref),
                "cpe_confidence": sum(1 for f in findings if f.match_confidence == "cpe"),
                "keyword_confidence": sum(1 for f in findings if f.match_confidence == "keyword"),
            },
            "findings": [
                {
                    "cve": f.cve, "asset": f.asset.identifier, "score": f.score,
                    "match_confidence": f.match_confidence, "cvss": f.cvss,
                    "epss": f.epss, "in_kev": f.in_kev,
                    "ransomware_associated": f.kev_known_ransomware,
                    "public_poc": f.has_poc_ref, "title": f.title,
                    "reasons": [{"component": r.component, "points": r.points,
                                 "evidence": r.evidence, "source": r.source} for r in f.reasons],
                } for f in findings
            ],
        }, indent=2))

    lines: list[str] = []
    lines.append(f"# Exposure Queue - {config.TOOL} v{config.VERSION}")
    lines.append("")
    lines.append(f"**Positioning:** {config.POSITIONING}")
    lines.append("")
    lines.append(f"**Disclaimer:** {config.DISCLAIMER}")
    lines.append("")
    kev_date = meta.get("kev_date", "unknown")
    epss_date = meta.get("epss_date", "unknown")
    n_kev = sum(1 for f in findings if f.in_kev)
    n_rw = sum(1 for f in findings if f.kev_known_ransomware)
    n_poc = sum(1 for f in findings if f.has_poc_ref)
    n_assets = len({f.asset.identifier for f in findings})
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Findings: **{len(findings)}** across {n_assets} asset(s)")
    lines.append(f"- CISA KEV listed: **{n_kev}** (catalog date: {kev_date})")
    lines.append(f"- Ransomware-associated: **{n_rw}**")
    lines.append(f"- With public PoC reference: **{n_poc}**")
    lines.append(f"- EPSS model: {epss_date}; scoring formula: CVSS ≤ {config.WEIGHTS['cvss']['max_points']} "
                 f"+ EPSS ≤ {config.WEIGHTS['epss']['max_points']} + KEV {config.WEIGHTS['kev']['points']} "
                 f"+ PoC {config.WEIGHTS['poc']['points']}, capped at {config.SCORE_CAP}")
    lines.append("")
    lines.append("## Queue (highest first)")
    lines.append("")
    for f in findings:
        lines.append(f"### {f.summary()}")
        lines.append("")
        if f.title:
            lines.append(f"> {f.title}")
            lines.append("")
        lines.append("**Why:**")
        lines.append("")
        for r in f.reasons:
            lines.append(f"- {r.line()}")
        lines.append("")
    mpath.write_text("\n".join(lines))
    return jpath, mpath
