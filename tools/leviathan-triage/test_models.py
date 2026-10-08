import unittest

from leviathan_triage import config
from leviathan_triage.models import (Asset, Finding, Reason, band_for,
                                     normalize, tokenize)


class TestNormalize(unittest.TestCase):
    def test_normalize_collapse(self):
        self.assertEqual(normalize("  Big-IP_F5  "), "big ip f5")

    def test_tokenize_multiword(self):
        self.assertEqual(tokenize("Exchange Server"), {"exchange", "server"})


class TestAsset(unittest.TestCase):
    def test_match_tokens_from_all_fields(self):
        a = Asset(identifier="x", vendor="Ivanti", product="Connect Secure",
                  keywords=["ive"])
        self.assertEqual(a.match_tokens(), {"ivanti", "connect", "secure", "ive"})

    def test_match_tokens_empty(self):
        self.assertEqual(Asset(identifier="bare").match_tokens(), set())


class TestBandFor(unittest.TestCase):
    def test_kev_only_is_p1(self):
        self.assertEqual(band_for(23.0, True, False, 0.20), "P1")

    def test_kev_ransomware_is_p0(self):
        self.assertEqual(band_for(15.0, True, True, 0.01), "P0")

    def test_kev_high_epss_is_p0(self):
        self.assertEqual(band_for(35.0, True, False, config.EPSS_P0_THRESHOLD), "P0")

    def test_kev_epss_just_under_p0(self):
        self.assertEqual(band_for(34.9, True, False, config.EPSS_P0_THRESHOLD - 0.01), "P1")

    def test_deep_kev_high_cvss_is_p0(self):
        self.assertEqual(band_for(51.0, True, False, 0.20, cvss=9.8), "P0")

    def test_not_kev_high_epss_is_p2(self):
        self.assertEqual(band_for(12.0, False, False, config.EPSS_P2_THRESHOLD), "P2")

    def test_not_kev_high_score_is_p2(self):
        self.assertEqual(band_for(config.SCORE_P2_MINIMUM, False, False, None), "P2")

    def test_not_kev_low_everything_is_p3(self):
        self.assertEqual(band_for(5.0, False, False, 0.05), "P3")

    def test_band_ordering_constants(self):
        self.assertEqual(config.BANDS, ("P0", "P1", "P2", "P3"))
        for b in config.BANDS:
            self.assertIn(b, config.BAND_COLORS)


class TestReasonAndFinding(unittest.TestCase):
    def test_reason_line_format(self):
        r = Reason("epss", 37.6, "EPSS probability 0.9400", "FIRST EPSS")
        self.assertEqual(r.line(), "[epss] +37.6 - EPSS probability 0.9400 (source: FIRST EPSS)")

    def test_finding_summary_and_flags(self):
        a = Asset(identifier="edge")
        f = Finding(cve="CVE-1-2", asset=a, score=95, band="P0", in_kev=True,
                    known_ransomware=True, has_poc=True, cvss=10.0)
        self.assertIn("KEV", f.flags())
        self.assertIn("ransomware-associated", f.flags())
        self.assertIn("public PoC", f.flags())
        self.assertIn("CVSS 10", f.summary())
        self.assertIn("P0", f.summary())

    def test_reasons_default_not_shared_between_findings(self):
        a = Asset(identifier="x")
        f1 = Finding(cve="CVE-1-1", asset=a, score=1)
        f2 = Finding(cve="CVE-1-2", asset=a, score=2)
        f1.reasons.append(Reason("match", 0, "e", "s"))
        self.assertEqual(f2.reasons, [])


if __name__ == "__main__":
    unittest.main()
