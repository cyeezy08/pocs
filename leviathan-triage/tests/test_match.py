import unittest

from leviathan_triage.match import match_all, match_asset_kev
from leviathan_triage.models import Asset, KevEntry


def ke(cve="CVE-2024-3400", vendor="Palo Alto", product="GlobalProtect"):
    return KevEntry(cve=cve, vendor_project=vendor, product=product,
                    date_added="2024-04-12", known_ransomware=True,
                    short_description="x")


class TestKeywordMatching(unittest.TestCase):
    def test_multiword_product_subset(self):
        a = Asset(identifier="ngfw", vendor="palo alto", product="globalprotect")
        self.assertEqual(match_asset_kev(a, ke()), "keyword")

    def test_keywords_alone_can_match(self):
        a = Asset(identifier="edge", keywords=["globalprotect"])
        self.assertEqual(match_asset_kev(a, ke()), "keyword")

    def test_partial_product_no_match(self):
        a = Asset(identifier="fw", keywords=["global protect only half"])
        # product tokens {globalprotect} not covered
        self.assertIsNone(match_asset_kev(a, ke()))

    def test_vendor_agreement_required(self):
        a = Asset(identifier="x", vendor="chrome", product="browser",
                  keywords=["globalprotect browser"])
        # asset tokens cover globalprotect? no -> need one covering product too
        a2 = Asset(identifier="x", vendor="foo", product="globalprotect",
                   keywords=["globalprotect"])
        self.assertIsNone(match_asset_kev(a2, ke(vendor="Palo Alto")))  # vendor clash

    def test_empty_asset_never_matches(self):
        self.assertIsNone(match_asset_kev(Asset(identifier="bare"), ke()))


class TestCpeMatching(unittest.TestCase):
    def test_cpe_path_when_all_declared(self):
        a = Asset(identifier="ngfw", vendor="palo_alto", product="globalprotect",
                  cpe="cpe:2.3:a:paloaltonetworks:globalprotect:5.2:*:*:*:*:*:*:*")
        # vendor token agreement: {palo alto} vs {palo alto} ok
        self.assertEqual(match_asset_kev(a, ke()), "cpe")

    def test_cpe_requires_vendor_and_product(self):
        a = Asset(identifier="x", cpe="cpe:2.3:a:x:y", product="globalprotect")
        self.assertEqual(match_asset_kev(a, ke()), "keyword")  # falls back


class TestMatchAll(unittest.TestCase):
    def test_dedupe_on_cve_asset(self):
        a = Asset(identifier="ngfw", keywords=["globalprotect"])
        a2 = Asset(identifier="dup", keywords=["globalprotect"],
                   vendor="palo alto")
        catalog = {"CVE-2024-3400": ke()}
        hits = match_all([a, a2], catalog)
        # same CVE different assets are separate findings
        self.assertEqual(len(hits), 2)
        self.assertEqual({h[0] for h in hits}, {"CVE-2024-3400"})

    def test_no_cross_asset_dedupe_collision(self):
        a = Asset(identifier="a", keywords=["globalprotect"])
        catalog = {"CVE-1": ke(), "CVE-2": ke(cve="CVE-2")}
        self.assertEqual(len(match_all([a], catalog)), 2)


if __name__ == "__main__":
    unittest.main()
