import json

from leviathan_core.models import Asset, Finding, Reason
from leviathan_core.report import write_reports


def test_report_counts_derived_not_typed(tmp_path):
    a = Asset(identifier="mail.acme.test", vendor="acme", product="super server")
    f1 = Finding(cve="CVE-2026-0001", asset=a, score=98.2, in_kev=True,
                 kev_known_ransomware=True, has_poc_ref=True, match_confidence="cpe",
                 reasons=[Reason("kev", 15, "in KEV (added 2026-09-01)", "CISA KEV")])
    f2 = Finding(cve="CVE-2026-0002", asset=a, score=20.0, match_confidence="keyword",
                 reasons=[Reason("epss", 20.0, "EPSS 0.5", "FIRST EPSS")])
    jpath, mpath = write_reports([f1, f2], tmp_path,
                                 {"kev_date": "2026-09-10", "epss_date": "2026-09-15"})
    data = json.loads(jpath.read_text())
    assert data["counts"] == {
        "findings": 2, "in_kev": 1, "ransomware_associated": 1,
        "with_public_poc": 1, "cpe_confidence": 1, "keyword_confidence": 1,
    }
    md = mpath.read_text()
    assert "Findings: **2**" in md
    assert "98.2" in md and "CVE-2026-0001" in md
    assert md.index("CVE-2026-0001") < md.index("CVE-2026-0002")  # sorted desc
    assert config_disclaimer_present(md)


def config_disclaimer_present(md: str) -> bool:
    from leviathan_core import config
    return config.DISCLAIMER[:40] in md
