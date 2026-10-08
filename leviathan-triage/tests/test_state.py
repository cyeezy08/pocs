import tempfile
import unittest
from pathlib import Path

from leviathan_triage.models import Asset
from leviathan_triage.state import State, finding_key
from leviathan_triage.score import score_finding
from leviathan_triage.models import KevEntry


def f(cve="CVE-2024-3400", asset="ngfw"):
    entry = KevEntry(cve=cve, vendor_project="Palo Alto", product="GlobalProtect",
                     date_added="2024-04-12", known_ransomware=False, short_description="")
    return score_finding(cve, Asset(identifier=asset), entry, 0.9, {}, "keyword")


class TestState(unittest.TestCase):
    def test_new_then_seen(self):
        with tempfile.TemporaryDirectory() as d:
            s = State(Path(d) / "state.json")
            finding = f()
            self.assertTrue(s.is_new(finding))
            self.assertEqual(s.mark([finding]), 1)
            self.assertFalse(s.is_new(finding))
            self.assertEqual(s.mark([finding]), 0)

    def test_key_separates_assets(self):
        self.assertNotEqual(finding_key(f(asset="a")), finding_key(f(asset="b")))

    def test_survives_reload(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            s1 = State(p)
            s1.mark([f()])
            s2 = State(p)
            self.assertFalse(s2.is_new(f()))

    def test_corrupt_state_starts_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            p.write_text("{broken json")
            s = State(p)
            self.assertTrue(s.is_new(f()))

    def test_wrong_schema_starts_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            p.write_text('{"schema": 99, "seen": {}}')
            self.assertTrue(State(p).is_new(f()))

    def test_atomic_write_leaves_no_tmp(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            s = State(p)
            s.mark([f()])
            self.assertFalse((Path(d) / "state.tmp").exists())
            self.assertTrue(p.exists())


if __name__ == "__main__":
    unittest.main()
