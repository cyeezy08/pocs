import gzip
import json
import tempfile
import unittest
from pathlib import Path

from leviathan_triage.feeds import Feeds
from leviathan_triage.http import Response, TransportError

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MIRROR_URL = "https://kevin.gtfkd.com/kev?page=1"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3400"

KEV_DOC = {
    "dateReleased": "2026-09-10T00:00:00Z",
    "vulnerabilities": [
        {"cve": "CVE-2024-3400", "vendorProject": "Palo Alto",
         "product": "GlobalProtect", "dateAdded": "2024-04-12",
         "knownRansomwareCampaignUse": "Known", "shortDescription": "cmd injection"},
        {"cve": "CVE-2023-34362", "vendorProject": "Ivanti",
         "product": "Connect Secure", "dateAdded": "2023-06-01",
         "knownRansomwareCampaignUse": "Unknown", "shortDescription": "auth bypass"},
    ],
}

EPSS_CSV = ("#model: v2026.09.01\n"
            "cve,epss,percentile\n"
            "CVE-2024-3400,0.94,0.99\n"
            "CVE-2023-34362,0.20,0.60\n"
            "BADLINE-1,0.5,0.5\n")

NVD_DOC = {"vulnerabilities": [{"cve": {"containers": {"cna": {
    "descriptions": [{"value": "Palo Alto command injection"}],
    "references": [{"url": "https://example.com/advisory"},
                   {"url": "https://github.com/x/exploit"}],
    "metrics": {"cvssV3_1": [{"cvssData": {"baseScore": 10.0,
                                           "baseSeverity": "CRITICAL"}}]},
}}}}]}


class FakeGet:
    def __init__(self, routes):
        self.routes = routes      # url -> Response | Exception
        self.calls = []

    def __call__(self, url, timeout, headers):
        self.calls.append(url)
        r = self.routes.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            return Response(404, b"missing")
        return r


class TestKevChain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "cache"

    def tearDown(self):
        self.tmp.cleanup()

    def test_cisa_primary(self):
        t = FakeGet({CISA_URL: Response(200, json.dumps(KEV_DOC).encode())})
        feeds = Feeds(self.cache, transport=t)
        kev = feeds.kev()
        self.assertEqual(len(kev), 2)
        self.assertEqual(kev["CVE-2024-3400"].product, "GlobalProtect")
        self.assertTrue(kev["CVE-2024-3400"].known_ransomware)
        self.assertEqual(feeds.kev_source(), "cisa.gov")
        self.assertIn(CISA_URL, t.calls)

    def test_mirror_fallback_on_403(self):
        t = FakeGet({CISA_URL: Response(403, b"forbidden"),
                     MIRROR_URL: Response(200, json.dumps(
                         {"vulnerabilities": KEV_DOC["vulnerabilities"],
                          "total_pages": 1}).encode())})
        feeds = Feeds(self.cache, transport=t)
        kev = feeds.kev()
        self.assertEqual(len(kev), 2)
        self.assertEqual(feeds.kev_source(), "mirror:kevin.gtfkd.com")

    def test_all_sources_fail_raises(self):
        t = FakeGet({CISA_URL: Response(500, b"nope"),
                     MIRROR_URL: Response(500, b"nope")})
        feeds = Feeds(self.cache, transport=t)
        with self.assertRaises(TransportError):
            feeds.kev()

    def test_mirror_cveid_schema_accepted(self):
        # the mirror speaks the official cveID field name - must parse
        mirror_doc = {"vulnerabilities": [
            {"cveID": "CVE-2026-76461", "vendorProject": "Cisco",
             "product": "Secure Email Gateway", "dateAdded": "2026-09-14",
             "knownRansomwareCampaignUse": "Unknown",
             "shortDescription": "inj"}],
            "total_pages": 1}
        t = FakeGet({CISA_URL: Response(403, b"forbidden"),
                     MIRROR_URL: Response(200, json.dumps(mirror_doc).encode())})
        feeds = Feeds(self.cache, transport=t)
        kev = feeds.kev()
        self.assertIn("CVE-2026-76461", kev)
        self.assertEqual(kev["CVE-2026-76461"].product, "Secure Email Gateway")

    def test_empty_200_response_is_a_failure_not_a_sync(self):
        # regression: a 200 with zero parseable entries poisoned the cache
        # with an empty catalog and the queue went silently blind
        t = FakeGet({CISA_URL: Response(403, b"forbidden"),
                     MIRROR_URL: Response(200, b'{"vulnerabilities": [], "total_pages": 1}')})
        feeds = Feeds(self.cache, transport=t)
        with self.assertRaises(TransportError):
            feeds.kev()
        self.assertFalse((self.cache / "kev.json").exists())  # nothing cached

    def test_dual_schema_cve_key(self):
        doc = {"vulnerabilities": [
            {"cve": "CVE-1-1", "vendorProject": "A", "product": "B",
             "dateAdded": "2026-01-01", "knownRansomwareCampaignUse": "Unknown",
             "shortDescription": "x"},
            {"cveID": "CVE-1-2", "vendorProject": "C", "product": "D",
             "dateAdded": "2026-01-02", "knownRansomwareCampaignUse": "Known",
             "shortDescription": "y"}]}
        t = FakeGet({CISA_URL: Response(200, json.dumps(doc).encode())})
        kev = Feeds(self.cache, transport=t).kev()
        self.assertEqual(set(kev), {"CVE-1-1", "CVE-1-2"})
        self.assertTrue(kev["CVE-1-2"].known_ransomware)

    def test_cache_hit_within_ttl_makes_no_calls(self):
        t = FakeGet({CISA_URL: Response(200, json.dumps(KEV_DOC).encode())})
        feeds = Feeds(self.cache, transport=t)
        feeds.kev()
        feeds2 = Feeds(self.cache, transport=t)
        feeds2.kev()
        self.assertEqual(t.calls.count(CISA_URL), 1)

    def test_stale_cache_refetches(self):
        t = FakeGet({CISA_URL: Response(200, json.dumps(KEV_DOC).encode())})
        feeds = Feeds(self.cache, transport=t, now=lambda: 1000.0)
        feeds.kev()
        feeds2 = Feeds(self.cache, transport=t, now=lambda: 1000.0 + 10 * 3600)
        feeds2.kev()
        self.assertEqual(t.calls.count(CISA_URL), 2)

    def test_in_memory_cache_avoids_reparse(self):
        t = FakeGet({CISA_URL: Response(200, json.dumps(KEV_DOC).encode())})
        feeds = Feeds(self.cache, transport=t)
        feeds.kev()
        feeds.kev()
        self.assertEqual(t.calls.count(CISA_URL), 1)

    def test_kev_newest_sorted(self):
        t = FakeGet({CISA_URL: Response(200, json.dumps(KEV_DOC).encode())})
        feeds = Feeds(self.cache, transport=t)
        newest = feeds.kev_newest(2)
        self.assertEqual(newest[0].cve, "CVE-2024-3400")  # 2024-04-12 newest


class TestEpss(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "cache"

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_and_cache(self):
        t = FakeGet({EPSS_URL: Response(200, gzip.compress(EPSS_CSV.encode()))})
        feeds = Feeds(self.cache, transport=t)
        scores = feeds.epss()
        self.assertAlmostEqual(scores["CVE-2024-3400"], 0.94)
        self.assertNotIn("BADLINE-1", scores)
        self.assertIn("v2026.09.01", feeds.epss_model_date())

    def test_cache_hit_no_second_fetch(self):
        t = FakeGet({EPSS_URL: Response(200, gzip.compress(EPSS_CSV.encode()))})
        Feeds(self.cache, transport=t).epss()
        Feeds(self.cache, transport=t).epss()
        self.assertEqual(len(t.calls), 1)

    def test_http_error_raises(self):
        t = FakeGet({EPSS_URL: Response(503, b"down")})
        feeds = Feeds(self.cache, transport=t)
        with self.assertRaises(TransportError):
            feeds.epss()


class TestNvd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "cache"

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_score_refs_and_cache(self):
        t = FakeGet({NVD_URL: Response(200, json.dumps(NVD_DOC).encode())})
        feeds = Feeds(self.cache, transport=t)
        out = feeds.nvd_batch(["CVE-2024-3400"], delay=0)
        self.assertEqual(out["CVE-2024-3400"]["cvss"], 10.0)
        self.assertTrue(any("github.com/x/exploit" in u
                            for u in out["CVE-2024-3400"]["refs"]))

    def test_cached_forever(self):
        t = FakeGet({NVD_URL: Response(200, json.dumps(NVD_DOC).encode())})
        Feeds(self.cache, transport=t).nvd_batch(["CVE-2024-3400"], delay=0)
        Feeds(self.cache, transport=t).nvd_batch(["CVE-2024-3400"], delay=0)
        self.assertEqual(len(t.calls), 1)

    def test_http_error_degrades_not_raises(self):
        t = FakeGet({NVD_URL: Response(403, b"rate limited")})
        feeds = Feeds(self.cache, transport=t)
        out = feeds.nvd_batch(["CVE-2024-3400"], delay=0)
        self.assertIn("error", out["CVE-2024-3400"])

    def test_no_record_degrades(self):
        t = FakeGet({NVD_URL: Response(200, b'{"vulnerabilities": []}')})
        feeds = Feeds(self.cache, transport=t)
        out = feeds.nvd_batch(["CVE-2024-3400"], delay=0)
        self.assertIn("error", out["CVE-2024-3400"])


if __name__ == "__main__":
    unittest.main()
