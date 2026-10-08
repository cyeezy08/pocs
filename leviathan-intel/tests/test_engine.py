"""Unit tests for the pure engine modules (no DB / network needed)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.correlate import asset_matches_cve, parse_cpe
from engine.scoring import priority_score, triage_label


# ---------- scoring ----------

def test_score_known_weights():
    score, reasons = priority_score(cvss=9.8, epss=0.96, kev=True, public_poc=True)
    assert score == 98  # 39.2 + 38.4 + 15 + 5 = 97.6 -> 98 (clamped at 100 max)
    assert len(reasons) >= 4

def test_score_components_add_up():
    score, reasons = priority_score(cvss=5.0, epss=0.5, kev=False, public_poc=False)
    assert score == 40  # 20 + 20
    assert any("CVSS" in r for r in reasons)
    assert any("EPSS" in r for r in reasons)

def test_score_kev_only_bonus():
    score_low, _ = priority_score(5.0, 0.5, kev=False, public_poc=False)
    score_kev, _ = priority_score(5.0, 0.5, kev=True, public_poc=False)
    assert score_kev - score_low == 15

def test_score_none_inputs_are_safe():
    score, reasons = priority_score(None, None, kev=False, public_poc=False)
    assert score == 0
    assert reasons

def test_triage_labels():
    assert triage_label(90) == "critical"
    assert triage_label(65) == "high"
    assert triage_label(40) == "medium"
    assert triage_label(10) == "low"


# ---------- correlation ----------

APACHE = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
NGINX = "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"

def test_parse_cpe_basic():
    c = parse_cpe(APACHE)
    assert c["vendor"] == "apache"
    assert c["product"] == "http_server"
    assert c["version"] == "2.4.49"

def test_parse_cpe_rejects_garbage():
    assert parse_cpe(None) is None
    assert parse_cpe("not-a-cpe") is None
    assert parse_cpe("cpe:2.2:a:x:y:1") is None

def test_match_exact_version():
    nvd = [APACHE]
    matched, reason = asset_matches_cve(APACHE, nvd)
    assert matched
    assert "exact version" in reason

def test_match_wildcard_version():
    any_version = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
    matched, reason = asset_matches_cve(APACHE, [any_version])
    assert matched
    assert "any version" in reason

def test_no_cross_product_match():
    matched, _ = asset_matches_cve(APACHE, [NGINX])
    assert not matched

def test_no_match_on_different_exact_version():
    listed = "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"
    matched, _ = asset_matches_cve(APACHE, [listed])
    assert not matched

def test_unparsable_asset_cpe():
    matched, reason = asset_matches_cve("garbage", [APACHE])
    assert not matched
    assert reason
