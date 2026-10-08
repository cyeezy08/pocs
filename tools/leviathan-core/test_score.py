"""Scoring formula tests - the audited weights are contract, not suggestion."""
import pytest

from leviathan_core import config
from leviathan_core.models import Asset
from leviathan_core.feeds.kev import KevEntry
from leviathan_core.score import score_finding, _cvss_points, _epss_points


def entry(ransomware=False):
    return KevEntry(cve="CVE-2026-0001", vendor_project="acme", product="super Server",
                    date_added="2026-09-01", known_ransomware=ransomware,
                    short_description="test")


def asset():
    return Asset(identifier="edge.acme.test", vendor="acme", product="super Server",
                 keywords=["super server"])


def nvd(cvss=9.8, refs=None, error=None):
    return {"cvss": cvss, "cvss_version": "CRITICAL", "refs": refs or [],
            "title": "Super Server RCE", "error": error}


def test_cvss_scaling_matches_config():
    assert _cvss_points(10.0) == config.WEIGHTS["cvss"]["max_points"]
    assert _cvss_points(9.8) == 39.2
    assert _cvss_points(None) == 0.0


def test_epss_scaling_matches_config():
    assert _epss_points(1.0) == config.WEIGHTS["epss"]["max_points"]
    assert _epss_points(0.975) == 39.0
    assert _epss_points(None) == 0.0


def test_full_score_kev_epss_poc():
    f = score_finding("CVE-2026-0001", asset(), entry(ransomware=True), 0.975,
                      nvd(refs=["https://github.com/x/exploit-2026-0001"]), "cpe")
    expected = min(config.SCORE_CAP, 39.2 + 39.0 + 15 + 5)
    assert f.score == expected
    assert f.in_kev and f.kev_known_ransomware and f.has_poc_ref
    comps = {r.component for r in f.reasons}
    assert comps == {"match", "cvss", "epss", "kev", "poc"}


def test_score_caps_at_100():
    # 40 + 40 + 15 + 5 = 100 exactly - needs every component present
    f = score_finding("CVE-2026-0001", asset(), entry(), 1.0,
                      nvd(cvss=10.0, refs=["https://github.com/x/poc-2026-0001"]), "cpe")
    assert f.score == config.SCORE_CAP


def test_max_score_without_poc_is_95():
    # no PoC reference: 40 + 40 + 15 = 95 - the honest ceiling
    f = score_finding("CVE-2026-0001", asset(), entry(), 1.0, nvd(cvss=10.0), "cpe")
    assert f.score == 95.0


def test_every_contributing_component_has_reason():
    f = score_finding("CVE-2026-0001", asset(), entry(), 0.5, nvd(cvss=7.5), "keyword")
    nonzero = [r for r in f.reasons if r.points > 0]
    assert len(nonzero) >= 3  # cvss + epss + kev at minimum here
    for r in f.reasons:
        assert r.evidence and r.source


def test_degradation_is_honest_not_silent():
    # NVD fetch failed: cvss contributes 0 AND the reason says why
    f = score_finding("CVE-2026-0001", asset(), entry(), 0.5,
                      nvd(cvss=None, error="rate-limited"), "keyword")
    cvss_reasons = [r for r in f.reasons if r.component == "cvss"]
    assert any("rate-limited" in r.evidence for r in cvss_reasons)
    expected = min(config.SCORE_CAP, 0.0 + round(0.5 * 40, 1) + 15)
    assert f.score == expected


def test_poc_keyword_narrowness():
    # a random reference URL does NOT count as PoC
    has, _ = __import__("leviathan_core.score", fromlist=["_has_poc_ref"])._has_poc_ref(
        ["https://nvd.nist.gov/misc-page"])
    assert has is False
