"""Offline tests for the Sploitus PoC adapter (no network in CI)."""
from __future__ import annotations

import pytest

from ingest import poc_sync


SAMPLE = {
    "exploits": [
        {
            "title": "Exploit for CISA KEV List CVE-2024-3400",
            "score": 9.8,
            "href": "https://github.com/example/poc-3400",
            "type": "github",
            "published": "2026-01-15",
            "id": "AAA-111",
            "cve_list": ["CVE-2024-3400"],
        },
        {
            "title": "Some unrelated exploit",
            "score": 5.0,
            "href": "https://github.com/example/other",
            "type": "github",
            "published": "2026-02-01",
            "id": "BBB-222",
            "cve_list": ["CVE-2099-9999"],
        },
        {
            "title": "Exploit without direct href",
            "score": 7.5,
            "href": None,
            "type": "exploit-db",
            "published": "2026-03-01",
            "id": "CCC-333",
            "cve_list": ["cve-2024-3400"],
        },
    ],
    "exploits_total": 3,
}


@pytest.fixture()
def canned(monkeypatch):
    monkeypatch.setattr(poc_sync, "fetch_exploits", lambda *a, **k: SAMPLE)


def test_keeps_only_queried_cve(canned):
    pocs = poc_sync.pocs_for_cve("CVE-2024-3400")
    assert len(pocs) == 2  # unrelated exploit filtered out
    assert all(p["source"] == "sploitus" for p in pocs)
    assert {p["url"] for p in pocs} == {
        "https://github.com/example/poc-3400",
        "https://sploitus.com/exploit?id=CCC-333",
    }


def test_cve_match_is_case_insensitive(canned):
    assert len(poc_sync.pocs_for_cve("cve-2024-3400")) == 2


def test_permalink_fallback_when_no_href(canned):
    pocs = poc_sync.pocs_for_cve("CVE-2024-3400")
    fallback = [p for p in pocs if p["url"].startswith("https://sploitus.com")]
    assert fallback and fallback[0]["url"] == "https://sploitus.com/exploit?id=CCC-333"


def test_rejects_non_cve_query():
    with pytest.raises(ValueError):
        poc_sync.pocs_for_cve("not-a-cve")


def test_total_count_exposed(canned):
    assert poc_sync.fetch_exploits("CVE-2024-3400")["exploits_total"] == 3
