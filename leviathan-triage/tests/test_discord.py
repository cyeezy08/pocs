import json
import unittest

from leviathan_triage import config
from leviathan_triage.discord import (finding_embed, markdown_digest,
                                      post_webhook, queue_embeds,
                                      summary_embed)
from leviathan_triage.http import Response
from leviathan_triage.models import Asset, KevEntry
from leviathan_triage.score import score_finding


def f(cve="CVE-2024-3400", asset="ngfw", epss=0.94, ransomware=False, band=None):
    entry = KevEntry(cve=cve, vendor_project="Palo Alto", product="GlobalProtect",
                     date_added="2024-04-12", known_ransomware=ransomware,
                     short_description="command injection in GlobalProtect")
    return score_finding(cve, Asset(identifier=asset), entry, epss, {}, "keyword")


class TestFindingEmbed(unittest.TestCase):
    def test_title_has_band_score_cve(self):
        e = finding_embed(f())
        self.assertTrue(e["title"].startswith("P0 · CVE-2024-3400 · score"))
        self.assertEqual(e["color"], config.BAND_COLORS["P0"])

    def test_new_marker(self):
        self.assertTrue(finding_embed(f(), mark_new=True)["title"].startswith("[NEW]"))

    def test_reason_lines_in_why_field(self):
        e = finding_embed(f())
        why = e["fields"][-1]["value"]
        self.assertIn("[kev]", why)
        self.assertIn("[epss]", why)
        self.assertIn("[match]", why)

    def test_reason_overflow_note(self):
        big = f()
        from leviathan_triage.models import Reason
        big.reasons.extend(Reason("note", 0, "extra", "test") for _ in range(8))
        why = finding_embed(big)["fields"][-1]["value"]
        self.assertIn("more reasons", why)


class TestQueueEmbeds(unittest.TestCase):
    def test_never_exceeds_discord_limit(self):
        findings = [f(cve=f"CVE-2024-{i:05d}", asset="a") for i in range(12)]
        embeds = queue_embeds(findings)
        self.assertEqual(len(embeds), config.WEBHOOK_EMBED_LIMIT)
        # head(1) + body(limit-2) + overflow(1); 12 - 8 = 4 in the notice
        self.assertIn("4 more", embeds[-1]["title"])

    def test_small_queue_one_embed_per_finding(self):
        findings = [f(), f(cve="CVE-2023-34362", asset="vpn")]
        self.assertEqual(len(queue_embeds(findings)), 3)  # head + 2

    def test_summary_counts(self):
        s = summary_embed([f(), f(asset="x"), f(epss=0.1)])
        self.assertIn("3 findings", s["title"])
        self.assertIn("P0×2", s["description"])

    def test_markdown_digest_lists_every_reason(self):
        d = markdown_digest([f()])
        self.assertIn("## leviathan-triage", d)
        self.assertIn("[kev]", d)
        self.assertIn(config.DISCLAIMER, d)


class TestWebhookPost(unittest.TestCase):
    def test_posts_json_payload(self):
        sent = {}

        def transport(url, payload, timeout, headers):
            sent.update(url=url, payload=payload)
            return Response(204, b"")

        post_webhook("https://discord.com/api/webhooks/1/x",
                     queue_embeds([f()]), transport=transport)
        self.assertTrue(sent["url"].startswith("https://discord.com/api/webhooks/"))
        self.assertEqual(len(sent["payload"]["embeds"]), 2)
        self.assertEqual(sent["payload"]["username"], "leviathan-triage")

    def test_non_2xx_raises(self):
        def transport(url, payload, timeout, headers):
            return Response(429, b'{"message": "slow down"}')

        with self.assertRaises(RuntimeError) as ctx:
            post_webhook("https://discord.com/api/webhooks/1/x",
                         [summary_embed([])], transport=transport)
        self.assertIn("429", str(ctx.exception))

    def test_empty_embeds_rejected(self):
        def transport(url, payload, timeout, headers):
            return Response(204, b"")
        with self.assertRaises(ValueError):
            post_webhook("https://x", [], transport=transport)


if __name__ == "__main__":
    unittest.main()
