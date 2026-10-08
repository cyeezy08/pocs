import json
import tempfile
import unittest
from pathlib import Path

from leviathan_triage import assets as am
from leviathan_triage.models import Asset


class TestJsonLoader(unittest.TestCase):
    def test_top_level_array(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.json"
            p.write_text(json.dumps([
                {"identifier": "vpn", "vendor": "ivanti", "product": "connect secure"},
                {"product": "jenkins", "version": "2.4"},
            ]))
            got = am.load(p)
            self.assertEqual(len(got), 2)
            self.assertEqual(got[1].identifier, "jenkins")  # identifier backfilled

    def test_wrapped_assets_object(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.json"
            p.write_text(json.dumps({"assets": [{"identifier": "x"}]}))
            self.assertEqual(len(am.load(p)), 1)

    def test_invalid_json_is_loud(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.json"
            p.write_text("{not json")
            with self.assertRaises(am.AssetError):
                am.load(p)

    def test_entry_needs_identity(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.json"
            p.write_text(json.dumps([{"version": "1.0"}]))
            with self.assertRaises(am.AssetError):
                am.load(p)


class TestHttpxLoader(unittest.TestCase):
    def test_jsonl_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.jsonl"
            p.write_text("\n".join([
                json.dumps({"host": "edge.example.com", "tech": ["nginx", "WordPress"]}),
                json.dumps({"url": "https://ci.example.com"}),
            ]))
            got = am.load(p)
            self.assertEqual(got[0].identifier, "edge.example.com")
            self.assertEqual(got[0].keywords, ["nginx", "WordPress"])
            self.assertEqual(got[0].source, "httpx")
            self.assertEqual(got[1].identifier, "https://ci.example.com")

    def test_plain_text_rejected_loudly(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.jsonl"
            p.write_text("edge.example.com\n")
            with self.assertRaises(am.AssetError):
                am.load(p)


class TestLinesLoader(unittest.TestCase):
    def test_vendor_slash_product(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.txt"
            p.write_text("ivanti/connect secure\n# comment\n\nJenkins CI\n")
            got = am.load(p)
            self.assertEqual(got[0].vendor, "ivanti")
            self.assertEqual(got[0].product, "connect secure")
            self.assertEqual(got[1].keywords, ["Jenkins CI"])

    def test_missing_file(self):
        with self.assertRaises(am.AssetError):
            am.load("/nonexistent/assets.json")


class TestStarter(unittest.TestCase):
    def test_write_starter_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "assets.json"
            got = am.write_starter(p)
            self.assertGreaterEqual(len(got), 5)
            again = am.load(p)
            self.assertEqual(len(again), len(got))
            self.assertTrue(all(isinstance(a, Asset) for a in again))


if __name__ == "__main__":
    unittest.main()
