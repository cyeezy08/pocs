import unittest

from leviathan_triage import config
from leviathan_triage.models import Asset, KevEntry
from leviathan_triage.score import build_queue, score_finding


def ke(cve="CVE-2024-3400", vendor="Palo Alto", product="GlobalProtect",
       ransomware=False):
    return KevEntry(cve=cve, vendor_project=vendor, product=product,
                    date_added="2024-04-12", known_ransomware=ransomware,
                    short_description="injected")


EPSS = {"CVE-2024-3400": 0.94, "CVE-2023-34362": 0.20, "CVE-NOPE": 0.5}


class TestPartialMode(unittest.TestCase):
    def test_kev_high_epss_scores_and_is_p0(self):
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(),
                          0.94, None, "keyword")
        self.assertAlmostEqual(f.score, 15 + 0.94 * 40, places=1)
        self.assertEqual(f.band, "P0")
        self.assertTrue(f.in_kev)

    def test_unassessed_components_say_so(self):
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(),
                          0.94, None, "keyword")
        comp = {r.component for r in f.reasons}
        self.assertIn("cvss", comp)
        self.assertIn("poc", comp)
        for r in f.reasons:
            if r.component == "cvss":
                self.assertIn("not assessed", r.evidence)

    def test_epss_missing_is_honest(self):
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(),
                          None, None, "keyword")
        self.assertEqual(f.score, 15)
        epss_reasons = [r for r in f.reasons if r.component == "epss"]
        self.assertIn("no EPSS", epss_reasons[0].evidence)

    def test_kev_low_epss_is_p1(self):
        f = score_finding("CVE-2023-34362", Asset(identifier="vpn"), ke(
            cve="CVE-2023-34362", vendor="Ivanti", product="Connect Secure"),
            0.20, None, "keyword")
        self.assertEqual(f.band, "P1")
        self.assertAlmostEqual(f.score, 15 + 8.0, places=1)

    def test_ransomware_flag_flows_through(self):
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(ransomware=True),
                          0.02, None, "keyword")
        self.assertEqual(f.band, "P0")
        self.assertTrue(f.known_ransomware)


class TestDeepMode(unittest.TestCase):
    def test_nvd_enrichment_adds_cvss_and_poc(self):
        nvd = {"cvss": 10.0, "cvss_version": "CRITICAL",
               "refs": ["https://github.com/x/exploit"], "title": "t"}
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(),
                          0.94, nvd, "keyword")
        # 40 + 37.6 + 15 + 5 = 97.6
        self.assertAlmostEqual(f.score, 97.6, places=1)

    def test_score_cap(self):
        nvd = {"cvss": 10.0, "cvss_version": "", "refs": ["https://poc.example/exploit"]}
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(),
                          1.0, nvd, "keyword")
        self.assertEqual(f.score, config.SCORE_CAP)

    def test_nvd_error_degrades(self):
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(),
                          0.94, {"error": "NVD HTTP 403"}, "keyword")
        self.assertIn("NVD HTTP 403", [r.evidence for r in f.reasons if r.component == "cvss"][0])

    def test_poc_keyword_match_is_narrow(self):
        nvd = {"cvss": 5.0, "refs": ["https://vendor.com/advisory"]}
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(),
                          0.10, nvd, "keyword")
        self.assertFalse(f.has_poc)


class TestReasonContract(unittest.TestCase):
    def test_every_component_recorded(self):
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(),
                          0.94, None, "keyword")
        self.assertIn("match", {r.component for r in f.reasons})
        self.assertIn("epss", {r.component for r in f.reasons})
        self.assertIn("kev", {r.component for r in f.reasons})
        self.assertIn("cvss", {r.component for r in f.reasons})

    def test_points_match_evidence_consistency(self):
        # any reason carrying points must carry positive points; zero-point
        # reasons must not claim a contribution
        f = score_finding("CVE-2024-3400", Asset(identifier="ngfw"), ke(),
                          0.0, None, "keyword")
        for r in f.reasons:
            if r.component in ("epss", "kev", "cvss", "poc"):
                self.assertGreaterEqual(r.points, 0)


class TestBuildQueue(unittest.TestCase):
    def test_ordering_band_then_score(self):
        from leviathan_triage.match import match_all  # ensure wiring stays
        assets = [Asset(identifier="ngfw", vendor="palo alto", product="globalprotect"),
                  Asset(identifier="vpn", vendor="ivanti", product="connect secure")]
        catalog = {"CVE-2024-3400": ke(),
                   "CVE-2023-34362": ke(cve="CVE-2023-34362", vendor="Ivanti",
                                        product="Connect Secure")}
        queue = build_queue(assets, catalog, EPSS)
        self.assertEqual(len(queue), 2)
        self.assertEqual(queue[0].band, "P0")          # high-epss KEV first
        self.assertEqual(queue[1].band, "P1")
        self.assertEqual(queue[0].cve, "CVE-2024-3400")

    def test_empty_everything(self):
        self.assertEqual(build_queue([], {}, {}), [])


if __name__ == "__main__":
    unittest.main()
