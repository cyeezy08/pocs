"""Explainable priority scoring for findings.

Every score ships with itemized reasons so a customer (or auditor) can see
exactly WHY a finding is prioritized - same philosophy as explainable ML:
no magic numbers reaching the dashboard.
"""
from __future__ import annotations

MAX_FROM_CVSS = 40.0
MAX_FROM_EPSS = 40.0
KEV_BONUS = 15.0
POC_BONUS = 5.0


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def priority_score(
    cvss: float | None,
    epss: float | None,
    kev: bool,
    public_poc: bool,
) -> tuple[int, list[str]]:
    """Return (priority 0-100, reasons list).

    Components:
      - CVSS v3.1 base score  -> up to 40 points  (raw severity)
      - EPSS probability      -> up to 40 points  (real-world exploitation likelihood)
      - CISA KEV membership   -> +15 points       (confirmed in-the-wild exploitation)
      - Public PoC available  -> +5 points        (friction to exploit is low)
    """
    reasons: list[str] = []

    cvss_c = _clamp(float(cvss or 0.0), 0.0, 10.0)
    epss_c = _clamp(float(epss or 0.0), 0.0, 1.0)

    score = MAX_FROM_CVSS * (cvss_c / 10.0)
    reasons.append(f"CVSS {cvss_c:.1f} -> {MAX_FROM_CVSS * (cvss_c / 10.0):.0f}/{MAX_FROM_CVSS:.0f}")

    score += MAX_FROM_EPSS * epss_c
    reasons.append(f"EPSS {epss_c:.4f} -> {MAX_FROM_EPSS * epss_c:.0f}/{MAX_FROM_EPSS:.0f}")

    if kev:
        score += KEV_BONUS
        reasons.append(f"In CISA KEV -> +{KEV_BONUS:.0f}")

    if public_poc:
        score += POC_BONUS
        reasons.append(f"Public PoC available -> +{POC_BONUS:.0f}")

    return min(int(round(score)), 100), reasons


def triage_label(priority: int) -> str:
    """Human-facing label for a priority value."""
    if priority >= 80:
        return "critical"
    if priority >= 60:
        return "high"
    if priority >= 35:
        return "medium"
    return "low"
