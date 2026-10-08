import json
import unittest

from leviathan_triage import config
from leviathan_triage.commands import (cmd_help, cmd_kev_today, cmd_queue,
                                       cmd_triage_cve, cmd_triage_product,
                                       interaction_options,
                                       respond_to_interaction)
from leviathan_triage.feeds import Feeds
from leviathan_triage.models import Asset, KevEntry


class FakeFeeds:
    """Feeds stand-in with preset data - no IO at all."""

    def __init__(self, kev, epss, nvd=None):
        self._kev, self._epss, self._nvd = kev, epss, nvd or {}

    def kev(self, force=False, max_age=None):
        return self._kev

    def epss(self, force=False, max_age=None):
        return self._epss

    def kev_source(self):
        return "test:cisa.gov"

    def epss_model_date(self):
        return "model: test"

    def kev_newest(self, limit=10):
        return sorted(self._kev.values(), key=lambda e: e.date_added, reverse=True)[:limit]

    def nvd_batch(self, cves, api_key="", delay=None):
        return {c: self._nvd.get(c, {"error": "not in fixture"}) for c in cves}


def entry(cve, vendor, product, date, ransomware=False, desc="desc"):
    return KevEntry(cve=cve, vendor_project=vendor, product=product,
                    date_added=date, known_ransomware=ransomware,
                    short_description=desc)


KEV = {
    "CVE-2024-3400": entry("CVE-2024-3400", "Palo Alto Networks", "PAN-OS",
                           "2024-04-12", True,
                           desc="PAN-OS GlobalProtect command injection"),
    "CVE-2023-34362": entry("CVE-2023-34362", "Ivanti", "Connect Secure",
                            "2023-06-01", desc="auth bypass"),
    "CVE-2021-41773": entry("CVE-2021-41773", "Apache", "HTTP Server",
                            "2021-10-28", desc="path traversal and RCE"),
}
EPSS = {"CVE-2024-3400": 0.94, "CVE-2023-34362": 0.20}


class TestTriageCve(unittest.TestCase):
    def test_known_cve_scores(self):
        e = cmd_triage_cve("cve-2024-3400", FakeFeeds(KEV, EPSS))
        self.assertTrue(e["title"].startswith("P0"))
        self.assertIn("CVE-2024-3400", e["title"])

    def test_malformed_id_rejected(self):
        e = cmd_triage_cve("root", FakeFeeds(KEV, EPSS))
        self.assertEqual(e["title"], "triage error")

    def test_unknown_cve_honest(self):
        e = cmd_triage_cve("CVE-1999-0001", FakeFeeds(KEV, EPSS))
        self.assertIn("neither KEV nor", e["description"])

    def test_not_in_kev_but_epss(self):
        epss = dict(EPSS, **{"CVE-2026-9999": 0.8})
        e = cmd_triage_cve("CVE-2026-9999", FakeFeeds(KEV, epss))
        self.assertTrue(e["title"].startswith("P2"))


class TestTriageProduct(unittest.TestCase):
    def test_ranked_path_via_description(self):
        # KEV product says PAN-OS; GlobalProtect lives only in the description
        e = cmd_triage_product("palo alto globalprotect", FakeFeeds(KEV, EPSS))
        self.assertIn("matches", e["title"])
        self.assertIn("CVE-2024-3400", e["fields"][0]["name"])

    def test_exact_path_multiword(self):
        e = cmd_triage_product("connect secure", FakeFeeds(KEV, EPSS))
        self.assertIn("1 matches", e["title"])
        self.assertIn("CVE-2023-34362", e["fields"][0]["name"])

    def test_vendor_agreement_blocks_cross_match(self):
        # chromium query must not surface Chrome-vendor entries
        kev = {"CVE-2-2": entry("CVE-2-2", "Chrome", "Chrome",
                                "2026-01-01", desc="renderer bug")}
        e = cmd_triage_product("chromium browser", FakeFeeds(kev, EPSS))
        self.assertIn("no KEV matches", e["title"])

    def test_no_match_is_honest_not_green(self):
        e = cmd_triage_product("Microsoft Exchange", FakeFeeds(KEV, EPSS))
        self.assertIn("no KEV matches", e["title"])
        self.assertIn("not a clean bill of health", e["description"])


class TestKevToday(unittest.TestCase):
    def test_newest_first(self):
        e = cmd_kev_today(FakeFeeds(KEV, EPSS))
        self.assertIn("2024-04-12", e["title"])
        self.assertIn("CVE-2024-3400", e["fields"][0]["name"])


class TestQueue(unittest.TestCase):
    def test_no_assets_is_error(self):
        e = cmd_queue(FakeFeeds(KEV, EPSS), assets=None)
        self.assertEqual(e["title"], "triage error")
        self.assertIn("init-assets", e["description"])

    def test_queue_with_assets(self):
        # queue matching is high-precision (product tokens only) - declare
        # the token the KEV entry actually carries, like examples/assets.json
        assets = [Asset(identifier="ngfw", vendor="palo alto", product="pan-os",
                        keywords=["pan-os", "globalprotect"])]
        e = cmd_queue(FakeFeeds(KEV, EPSS), assets=assets)
        self.assertIn("1 findings", e["title"])
        self.assertIn("CVE-2024-3400", e["description"])

    def test_feed_failure_is_error_embed(self):
        class Dead:
            def kev(self, *a, **k):
                raise RuntimeError("all KEV sources failed")
        e = cmd_queue(Dead(), assets=[Asset(identifier="x")])
        self.assertIn("feed sync failed", e["description"])


class TestInteractionDispatch(unittest.TestCase):
    def test_options_parsed(self):
        d = {"data": {"name": "triage-cve",
                      "options": [{"name": "cve", "value": "CVE-2024-3400"}]}}
        self.assertEqual(interaction_options(d), {"cve": "CVE-2024-3400"})

    def test_routing(self):
        feeds = FakeFeeds(KEV, EPSS)
        r = respond_to_interaction({"data": {"name": "kev-today", "options": []}}, feeds)
        self.assertIn("KEV newest", r["embeds"][0]["title"])

    def test_unknown_falls_back_to_help(self):
        r = respond_to_interaction({"data": {"name": "nonsense", "options": []}}, FakeFeeds(KEV, EPSS))
        self.assertEqual(r["embeds"][0]["title"], "leviathan-triage")

    def test_help_embed_has_disclaimer(self):
        self.assertIn("no packets", cmd_help()["description"])

    def test_handler_exception_never_hangs_interaction(self):
        class Exploding:
            def kev(self, *a, **k):
                raise RuntimeError("boom")
        r = respond_to_interaction({"data": {"name": "queue", "options": []}},
                                   Exploding(), assets=[Asset(identifier="x")])
        self.assertIn("feed sync failed", r["embeds"][0]["description"])


if __name__ == "__main__":
    unittest.main()
