import pytest

from surfacediff.diff import diff_assets
from surfacediff.normalize import Asset


def a(key, attrs=None):
    kind, ident = key.split("|", 1)
    return Asset(kind, ident, attrs or {})


def test_added_removed():
    old = [a("host|old.example.com"), a("host|keep.example.com")]
    new = [a("host|new.example.com"), a("host|keep.example.com")]
    d = diff_assets(old, new)
    assert d["counts"] == {"added": 1, "removed": 1, "changed": 0}
    assert d["added"][0]["key"] == "host|new.example.com"
    assert d["removed"][0]["key"] == "host|old.example.com"
    assert d["has_changes"] is True


def test_changed_reports_field_delta():
    old = [a("url|https://x.example.com", {"status_code": 200, "title": "Home"})]
    new = [a("url|https://x.example.com", {"status_code": 403, "title": "Home"})]
    d = diff_assets(old, new)
    assert d["counts"]["changed"] == 1
    delta = d["changed"][0]["delta"]
    assert delta["changed"]["status_code"] == {"from": 200, "to": 403}


def test_identical_means_no_changes():
    recs = [a("host|x.example.com", {"ip": "1.2.3.4"})]
    d = diff_assets(recs, recs)
    assert d["has_changes"] is False
    assert d["counts"] == {"added": 0, "removed": 0, "changed": 0}


def test_attr_order_does_not_trigger_change():
    old = [a("url|https://x.example.com", {"tech": ["nginx", "php"]})]
    new = [a("url|https://x.example.com", {"tech": ["nginx", "php"]})]
    assert diff_assets(old, new)["has_changes"] is False


def test_sorted_output_is_deterministic():
    old = []
    new = [a("host|z.example.com"), a("host|a.example.com")]
    d = diff_assets(old, new)
    assert [r["key"] for r in d["added"]] == ["host|a.example.com", "host|z.example.com"]
