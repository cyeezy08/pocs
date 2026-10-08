"""Explainable scoring - the audited formula, with reasons on every finding.

score = min(cap, cvss_pts + epss_pts + kev_pts + poc_pts)

A finding with zero reasons is a bug; a component that contributes points
without recording evidence is a bug. Tests enforce both.
"""
from __future__ import annotations

from . import config
from .feeds.kev import KevEntry
from .feeds.nvd import enrich_batch
from .models import Asset, Finding, Reason
from pathlib import Path


def _cvss_points(cvss: float | None) -> float:
    if cvss is None:
        return 0.0
    return round((cvss / 10.0) * config.WEIGHTS["cvss"]["max_points"], 1)


def _epss_points(epss: float | None) -> float:
    if epss is None:
        return 0.0
    return round(epss * config.WEIGHTS["epss"]["max_points"], 1)


def _has_poc_ref(refs: list[str]) -> tuple[bool, str | None]:
    for url in refs:
        low = url.lower()
        if any(k in low for k in config.POC_REF_KEYWORDS):
            return True, url
    return False, None


def score_finding(
    cve: str,
    asset: Asset,
    entry: KevEntry | None,
    epss: float | None,
    nvd: dict,
    match_confidence: str,
) -> Finding:
    reasons: list[Reason] = []

    # match reason (always present - the queue must say WHY this asset is linked)
    evidence = f"{asset.identifier} matched {entry.vendor_project}/{entry.product}" if entry \
        else f"{asset.identifier} matched {cve}"
    reasons.append(Reason("match", 0.0, evidence, "asset inventory"))
    if match_confidence == "keyword":
        reasons.append(Reason("match", 0.0,
                              "product-level keyword match; version not verified (Phase 3 adds range checks)",
                              "match.py"))

    cvss = nvd.get("cvss")
    cvss_pts = _cvss_points(cvss)
    if cvss is not None:
        reasons.append(Reason("cvss", cvss_pts,
                              f"CVSS base {cvss} ({nvd.get('cvss_version', '')})",
                              "NVD"))
    else:
        reasons.append(Reason("cvss", 0.0,
                              nvd.get("error") or "CVSS unavailable",
                              "NVD"))

    epss_pts = _epss_points(epss)
    if epss is not None:
        reasons.append(Reason("epss", epss_pts,
                              f"EPSS probability {epss:.4f} (~{round(epss * 100)}% chance of exploitation in the wild within 30 days)",
                              "FIRST EPSS"))
    else:
        reasons.append(Reason("epss", 0.0, "EPSS score unavailable for this CVE", "FIRST EPSS"))

    kev_pts = 0.0
    in_kev = entry is not None
    if in_kev:
        kev_pts = float(config.WEIGHTS["kev"]["points"])
        reasons.append(Reason("kev", kev_pts,
                              f"in CISA KEV (added {entry.date_added})"
                              + (" - associated with known ransomware campaigns" if entry.known_ransomware else ""),
                              "CISA KEV"))

    poc_pts = 0.0
    has_poc, poc_url = _has_poc_ref(nvd.get("refs", []))
    if has_poc and poc_url:
        poc_pts = float(config.WEIGHTS["poc"]["points"])
        reasons.append(Reason("poc", poc_pts, f"public PoC reference: {poc_url}", "NVD references"))

    total = min(config.SCORE_CAP, cvss_pts + epss_pts + kev_pts + poc_pts)
    return Finding(
        cve=cve, asset=asset, score=total, reasons=reasons,
        match_confidence=match_confidence, cvss=cvss, epss=epss,
        in_kev=in_kev,
        kev_known_ransomware=bool(entry and entry.known_ransomware),
        has_poc_ref=has_poc, title=nvd.get("title", ""),
    )


def score_matches(
    matches: list[tuple[str, Asset, KevEntry, str]],
    epss: dict[str, float],
    cache_dir: Path,
) -> list[Finding]:
    """Enrich matched CVEs (NVD, cached) and score them all."""
    cves = sorted({cve for cve, *_ in matches})
    nvd_data = enrich_batch(cves, cache_dir)
    findings = [
        score_finding(cve, asset, entry, epss.get(cve), nvd_data.get(cve, {}), conf)
        for cve, asset, entry, conf in matches
    ]
    findings.sort(key=lambda f: (-f.score, f.cve, f.asset.identifier))
    return findings
