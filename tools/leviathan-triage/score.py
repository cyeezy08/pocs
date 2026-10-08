"""Explainable scoring - the audited Leviathan formula, with reasons always.

score = min(cap, cvss_pts + epss_pts + kev_pts + poc_pts)

Partial mode (default, fast): EPSS + KEV are always assessed; CVSS and PoC
contribute 0 and record a reason saying "not assessed - use --deep".
Deep mode (--deep): NVD enrichment fills CVSS + PoC with real evidence.

A finding with zero reasons is a bug. A component that contributes points
without recording evidence is a bug. Tests enforce both.
"""
from __future__ import annotations

from typing import Optional

from . import config
from .models import Asset, Finding, KevEntry, Reason, band_for


def _cvss_points(cvss: Optional[float]) -> float:
    if cvss is None:
        return 0.0
    return round((cvss / 10.0) * config.WEIGHTS["cvss"]["max_points"], 1)


def _epss_points(epss: Optional[float]) -> float:
    if epss is None:
        return 0.0
    return round(epss * config.WEIGHTS["epss"]["max_points"], 1)


def _has_poc_ref(refs: list) -> tuple:
    for url in refs or []:
        low = url.lower()
        if any(k in low for k in config.POC_REF_KEYWORDS):
            return True, url
    return False, None


def score_finding(cve: str, asset: Asset, entry: Optional[KevEntry],
                  epss: Optional[float], nvd: Optional[dict],
                  match_confidence: str = "keyword") -> Finding:
    reasons: list = []

    if entry is not None:
        evidence = (f"{asset.identifier} matched "
                    f"{entry.vendor_project}/{entry.product}").strip("/")
        reasons.append(Reason("match", 0.0, evidence, "declared asset inventory"))
    else:
        reasons.append(Reason("match", 0.0,
                              f"{asset.identifier} requested directly for {cve}",
                              "direct lookup"))
    if match_confidence == "keyword":
        reasons.append(Reason(
            "match", 0.0,
            "product-level keyword match; version not verified "
            "(recorded as evidence, never trusted)",
            "match.py"))

    # EPSS - always assessed (bulk feed)
    epss_pts = _epss_points(epss)
    if epss is not None:
        reasons.append(Reason(
            "epss", epss_pts,
            f"EPSS probability {epss:.4f} (~{round(epss * 100)}% chance of "
            "in-the-wild exploitation within 30 days)",
            "FIRST EPSS"))
    else:
        reasons.append(Reason("epss", 0.0,
                              "no EPSS score for this CVE yet", "FIRST EPSS"))

    # KEV - the exploited-in-the-wild anchor
    kev_pts = 0.0
    in_kev = entry is not None
    if in_kev:
        kev_pts = float(config.WEIGHTS["kev"]["points"])
        reasons.append(Reason(
            "kev", kev_pts,
            f"in CISA KEV (added {entry.date_added})"
            + (" - known ransomware campaigns" if entry.known_ransomware else ""),
            "CISA KEV"))

    # CVSS + PoC - only in deep mode; partial mode says so honestly
    nvd = nvd or {}
    cvss = nvd.get("cvss")
    cvss_pts = _cvss_points(cvss)
    if cvss is not None:
        reasons.append(Reason("cvss", cvss_pts,
                              f"CVSS base {cvss:g} ({nvd.get('cvss_version') or 'v3.x'})",
                              "NVD"))
    elif "error" in nvd:
        reasons.append(Reason("cvss", 0.0, f"NVD enrichment failed: {nvd['error']}", "NVD"))
    else:
        reasons.append(Reason("cvss", 0.0,
                              "CVSS not assessed (use --deep for NVD enrichment)",
                              "NVD"))

    has_poc, poc_url = _has_poc_ref(nvd.get("refs", []))
    poc_pts = 0.0
    if has_poc and poc_url:
        poc_pts = float(config.WEIGHTS["poc"]["max_points"])
        reasons.append(Reason("poc", poc_pts,
                              f"public PoC reference: {poc_url}", "NVD references"))
    elif not nvd:
        reasons.append(Reason("poc", 0.0,
                              "PoC not assessed (use --deep for NVD references)",
                              "NVD references"))

    total = min(config.SCORE_CAP, epss_pts + kev_pts + cvss_pts + poc_pts)
    f = Finding(
        cve=cve, asset=asset, score=total, reasons=reasons,
        match_confidence=match_confidence, epss=epss,
        in_kev=in_kev,
        kev_date_added=entry.date_added if entry else "",
        known_ransomware=bool(entry and entry.known_ransomware),
        has_poc=has_poc, cvss=cvss,
        title=(nvd.get("title") or (entry.short_description if entry else ""))[:280],
    )
    f.band = band_for(total, in_kev, f.known_ransomware, epss, cvss)
    return f


def build_queue(assets: list, kev: dict, epss: dict,
                nvd: Optional[dict] = None) -> list:
    """Match + score everything. Sorted by band, then score, then cve."""
    from .match import match_all
    nvd = nvd or {}
    findings = []
    for cve, asset, entry, conf in match_all(assets, kev):
        findings.append(score_finding(cve, asset, entry,
                                      epss.get(cve), nvd.get(cve), conf))
    findings.sort(key=lambda f: (f.band, -f.score, f.cve, f.asset.identifier))
    return findings
