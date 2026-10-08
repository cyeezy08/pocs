import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

from leviathan_triage import cli
from leviathan_triage.feeds import Feeds


SEED_KEV = {
    "source": "test", "fetched_at": 9999999999.0,
    "dateReleased": "2026-09-10",
    "vulnerabilities": [
        {"cve": "CVE-2024-3400", "vendorProject": "Palo Alto",
         "product": "GlobalProtect", "dateAdded": "2024-04-12",
         "knownRansomwareCampaignUse": "Known", "shortDescription": "cmd inj"},
        {"cve": "CVE-2023-34362", "vendorProject": "Ivanti",
         "product": "Connect Secure", "dateAdded": "2023-06-01",
         "knownRansomwareCampaignUse": "Unknown", "shortDescription": "auth"},
    ],
}

SEED_EPSS = "cve,epss,percentile\nCVE-2024-3400,0.94,0.99\nCVE-2023-34362,0.20,0.60\n"


class CliCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sdir = Path(self.tmp.name) / "state"
        cache = self.sdir / "cache"
        cache.mkdir(parents=True)
        (cache / "kev.json").write_text(json.dumps(SEED_KEV))
        (cache / "epss.csv").write_text(SEED_EPSS)
        self.assets = Path(self.tmp.name) / "assets.json"

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = cli.main(["--state-dir", str(self.sdir), *argv])
            except SystemExit as e:  # helper funcs exit(2) on config errors
                code = e.code if isinstance(e.code, int) else 0
        return code, out.getvalue()


class TestTriage(CliCase):
    def test_first_run_alerts_second_is_quiet(self):
        from leviathan_triage import assets as am
        am.write_starter(self.assets)
        code, out = self.run_cli("--assets", str(self.assets), "triage", "--json")
        self.assertEqual(code, 1)               # new findings -> exit 1
        doc = json.loads(out)
        self.assertEqual(doc["new"], 2)
        self.assertEqual(doc["counts"], {"P0": 1, "P1": 1})
        code2, out2 = self.run_cli("--assets", str(self.assets), "triage", "--json")
        self.assertEqual(code2, 0)              # state marked -> quiet
        self.assertEqual(json.loads(out2)["new"], 0)

    def test_human_output_lists_reasons(self):
        from leviathan_triage import assets as am
        am.write_starter(self.assets)
        code, out = self.run_cli("--assets", str(self.assets), "triage")
        self.assertIn("[NEW]", out)
        self.assertIn("[kev]", out)
        self.assertIn("[epss]", out)

    def test_no_cache_is_exit_2(self):
        empty = Path(self.tmp.name) / "fresh"
        empty.mkdir()
        code, _ = self.run_cli("--state-dir", str(empty),
                               "--assets", str(self.assets), "triage")
        self.assertEqual(code, 2)

    def test_missing_assets_is_exit_2(self):
        code, _ = self.run_cli("triage")
        self.assertEqual(code, 2)


class TestAskAndCve(CliCase):
    def test_ask_product(self):
        code, out = self.run_cli("ask", "palo", "alto", "globalprotect")
        self.assertEqual(code, 0)
        self.assertIn("CVE-2024-3400", out)

    def test_ask_json(self):
        code, out = self.run_cli("--json", "ask", "globalprotect")
        doc = json.loads(out)
        self.assertIn("CVE-2024-3400", doc["fields"][0]["name"])

    def test_cve_direct(self):
        code, out = self.run_cli("cve", "CVE-2024-3400")
        self.assertEqual(code, 0)
        self.assertIn("P0", out)

    def test_kev_today(self):
        code, out = self.run_cli("kev-today")
        self.assertEqual(code, 0)
        self.assertIn("CVE-2024-3400", out)


class TestDaemon(CliCase):
    def test_once_no_post_no_webhook_needed(self):
        from leviathan_triage import assets as am
        am.write_starter(self.assets)
        code, out = self.run_cli("--assets", str(self.assets),
                                 "daemon", "--once", "--no-post")
        self.assertEqual(code, 1)
        self.assertIn("NEW", out)

    def test_once_quiet_after_state(self):
        from leviathan_triage import assets as am
        am.write_starter(self.assets)
        self.run_cli("--assets", str(self.assets), "daemon", "--once", "--no-post")
        code, out = self.run_cli("--assets", str(self.assets),
                                 "daemon", "--once", "--no-post")
        self.assertEqual(code, 0)
        self.assertIn("nothing new", out)

    def test_feed_failure_exit_2(self):
        empty = Path(self.tmp.name) / "fresh"
        empty.mkdir()
        from leviathan_triage import assets as am
        from leviathan_triage.http import TransportError
        am.write_starter(self.assets)

        class DeadFeeds:
            def __init__(self, *a, **k):
                pass

            def kev(self, *a, **k):
                raise TransportError("all KEV sources failed")

        with mock.patch.object(cli, "Feeds", DeadFeeds):
            code, _ = self.run_cli("--state-dir", str(empty), "--assets",
                                   str(self.assets), "daemon", "--once")
        self.assertEqual(code, 2)


class TestWebhookCommands(CliCase):
    def test_test_webhook_with_mock(self):
        posted = {}
        from leviathan_triage import discord
        with mock.patch.object(discord, "http_post_json",
                               side_effect=lambda url, payload, timeout=30, headers=None, transport=None:
                               posted.update(url=url, payload=payload) or
                               mock.Mock(status=204)):
            code, out = self.run_cli("test-webhook", "--webhook",
                                     "https://discord.com/api/webhooks/1/abc")
        self.assertEqual(code, 0)
        self.assertIn("webhook OK", out)
        self.assertEqual(posted["payload"]["embeds"][0]["title"],
                         "leviathan-triage wired")

    def test_webhook_missing_is_exit_2(self):
        env_backup = os.environ.pop("LT_DISCORD_WEBHOOK", None)
        try:
            code, _ = self.run_cli("test-webhook")
            self.assertEqual(code, 2)
        finally:
            if env_backup:
                os.environ["LT_DISCORD_WEBHOOK"] = env_backup

    def test_post_queue(self):
        from leviathan_triage import assets as am, discord
        am.write_starter(self.assets)
        posted = {}
        with mock.patch.object(discord, "http_post_json",
                               side_effect=lambda url, payload, timeout=30, headers=None, transport=None:
                               posted.update(payload=payload) or mock.Mock(status=204)):
            code, out = self.run_cli("--assets", str(self.assets), "post",
                                     "--webhook", "https://discord.com/api/webhooks/1/abc")
        self.assertEqual(code, 0)
        self.assertIn("posted 2 of 2", out)


class TestLanes(CliCase):
    """Two-lane routing: P0/P1 -> paid webhook realtime; digest -> free."""

    def setUp(self):
        super().setUp()
        from leviathan_triage import assets as am
        am.write_starter(self.assets)

    def test_paid_lane_routes_hot_only(self):
        from leviathan_triage import discord
        posts = []
        with mock.patch.object(
                discord, "post_webhook",
                side_effect=lambda url, embeds, **k:
                posts.append(url)):
            with mock.patch.dict(os.environ, {
                    "LT_DISCORD_WEBHOOK_PAID":
                        "https://discord.com/api/webhooks/9/paid"}):
                code, out = self.run_cli("--assets", str(self.assets),
                                         "--webhook",
                                         "https://discord.com/api/webhooks/1/free",
                                         "daemon", "--once", "--json")
        self.assertEqual(code, 1)
        doc = json.loads(out)
        self.assertTrue(doc["paid_lane"])
        self.assertEqual(doc["hot"], 2)          # starter queue is P0 + P1
        self.assertEqual(posts, ["https://discord.com/api/webhooks/9/paid"])

    def test_single_lane_unchanged_without_paid_env(self):
        from leviathan_triage import discord
        os.environ.pop("LT_DISCORD_WEBHOOK_PAID", None)
        posts = []
        with mock.patch.object(
                discord, "post_webhook",
                side_effect=lambda url, embeds, **k:
                posts.append(url)):
            code, _ = self.run_cli("--assets", str(self.assets), "--webhook",
                                   "https://discord.com/api/webhooks/1/free",
                                   "daemon", "--once")
        self.assertEqual(code, 1)
        self.assertEqual(posts, ["https://discord.com/api/webhooks/1/free"])

    def test_digest_posts_to_free_webhook_with_cta(self):
        from leviathan_triage import discord
        posts = []
        with mock.patch.object(
                discord, "post_webhook",
                side_effect=lambda url, embeds, **k:
                posts.append((url, embeds))):
            with mock.patch.dict(os.environ, {"LT_BUY_URL": "https://gum.co/levip0"}):
                code, out = self.run_cli("--assets", str(self.assets), "--webhook",
                                         "https://discord.com/api/webhooks/1/free",
                                         "digest")
        self.assertEqual(code, 0)
        url, embeds = posts[0]
        self.assertEqual(url, "https://discord.com/api/webhooks/1/free")
        self.assertEqual(len(embeds), 1)
        self.assertIn("gum.co/levip0", embeds[0]["fields"][0]["value"])

    def test_digest_no_post_prints_embed(self):
        code, out = self.run_cli("--assets", str(self.assets), "digest", "--no-post")
        self.assertEqual(code, 0)
        embed = json.loads(out)
        self.assertIn("digest", embed["title"])


class TestInitAndClean(CliCase):
    def test_init_assets_then_load(self):
        target = Path(self.tmp.name) / "my.json"
        code, out = self.run_cli("init-assets", str(target))
        self.assertEqual(code, 0)
        self.assertIn("demo assets", out)
        from leviathan_triage import assets as am
        self.assertGreaterEqual(len(am.load(target)), 5)

    def test_init_assets_no_overwrite(self):
        target = Path(self.tmp.name) / "my.json"
        target.write_text("[]")
        code, out = self.run_cli("init-assets", str(target))
        self.assertEqual(code, 0)
        self.assertIn("already exists", out)
        self.assertEqual(target.read_text(), "[]")

    def test_cache_clean(self):
        code, out = self.run_cli("cache-clean")
        self.assertEqual(code, 0)
        self.assertFalse((self.sdir / "cache" / "kev.json").exists())

    def test_sync_from_cache(self):
        code, out = self.run_cli("sync")
        self.assertEqual(code, 0)
        self.assertIn("KEV", out)


class TestRegister(CliCase):
    def test_register_requires_token(self):
        os.environ.pop("LT_DISCORD_BOT_TOKEN", None)
        code, _ = self.run_cli("register-commands")
        self.assertEqual(code, 2)

    def test_gateway_requires_token(self):
        os.environ.pop("LT_DISCORD_BOT_TOKEN", None)
        code, _ = self.run_cli("gateway")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
