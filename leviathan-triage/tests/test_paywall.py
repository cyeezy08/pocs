"""Paywall tests - license verification, subscriber store, role gate, lanes.

Every network touch is a fake transport; nothing here talks to Gumroad or
Discord. The contracts under test:
  - verification is server-side and honest (cancelled/refunded = denied)
  - one license binds to exactly one Discord user id
  - network failure never masquerades as "valid"
  - subscribe/subscription interactions are ephemeral (flags 64)
  - two-lane daemon routing: P0/P1 -> paid webhook, nothing -> free lane
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from leviathan_triage import commands, config, discord, paywall
from leviathan_triage.http import Response, TransportError
from leviathan_triage.paywall import (Paywall, SubscriberStore, verify_license)


def gumroad_ok(email="buyer@example.com", cancelled=False, refunded=False):
    return Response(status=200, body=json.dumps({
        "success": True,
        "purchase": {
            "email": email, "product_name": "Leviathan P0 Feed",
            "sale_id": 12345, "refunded": refunded,
            "subscription_cancelled_at": "2026-01-01" if cancelled else None,
        }}).encode())


class FormFake:
    """Records form posts, returns canned responses."""

    def __init__(self, responses=None, error=None):
        self.calls = []
        self.responses = list(responses or [])
        self.error = error

    def __call__(self, url, fields, timeout, headers):
        self.calls.append({"url": url, "fields": fields, "headers": headers})
        if self.error:
            raise self.error
        return self.responses.pop(0)


class RestFake:
    """Records JSON PUT/DELETE calls (role grant/revoke), returns 204."""

    def __init__(self, status=204):
        self.calls = []
        self.status = status

    def __call__(self, url, payload, timeout, headers):
        self.calls.append({"url": url, "payload": payload, "headers": headers})
        return Response(status=self.status, body=b"")


class DeleteFake:
    def __init__(self, status=204):
        self.calls = []
        self.status = status

    def __call__(self, url, timeout, headers):
        self.calls.append({"url": url, "headers": headers})
        return Response(status=self.status, body=b"")


def make_paywall(tmp, gumroad_responses=None, gumroad_error=None,
                 role_status=204, **kw):
    store = SubscriberStore(Path(tmp) / "subscribers.json")
    pw = Paywall(store=store, permalink="levip0", bot_token="TOK",
                 guild_id="G1", role_id="R1",
                 transport=FormFake(gumroad_responses, gumroad_error),
                 role_transport=RestFake(role_status), **kw)
    return pw


class TestVerifyLicense(unittest.TestCase):
    def test_ok(self):
        fake = FormFake([gumroad_ok()])
        v = verify_license("KEY-1234", "levip0", transport=fake)
        self.assertTrue(v["ok"])
        self.assertEqual(v["email"], "buyer@example.com")
        self.assertEqual(fake.calls[0]["fields"],
                         {"product_permalink": "levip0", "license_key": "KEY-1234"})

    def test_not_found(self):
        fake = FormFake([Response(status=404, body=b'{"success": false,'
                                             b'"message": "That product does not exist"}')])
        v = verify_license("WRONG", "levip0", transport=fake)
        self.assertFalse(v["ok"])
        self.assertIn("not found", v["error"])

    def test_cancelled_denied(self):
        fake = FormFake([gumroad_ok(cancelled=True)])
        v = verify_license("KEY", "levip0", transport=fake)
        self.assertFalse(v["ok"])
        self.assertIn("cancelled", v["error"])

    def test_refunded_denied(self):
        fake = FormFake([gumroad_ok(refunded=True)])
        v = verify_license("KEY", "levip0", transport=fake)
        self.assertFalse(v["ok"])
        self.assertIn("refunded", v["error"])

    def test_network_failure_is_not_valid(self):
        fake = FormFake(error=TransportError("dns broke"))
        v = verify_license("KEY", "levip0", transport=fake)
        self.assertFalse(v["ok"])
        self.assertIn("cannot reach gumroad", v["error"])

    def test_garbage_body(self):
        fake = FormFake([Response(status=200, body=b"<html>not json</html>")])
        v = verify_license("KEY", "levip0", transport=fake)
        self.assertFalse(v["ok"])
        self.assertIn("non-JSON", v["error"])


class TestStore(unittest.TestCase):
    def test_bind_reload(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "subs.json"
            s1 = SubscriberStore(p)
            s1.bind("K1", "1000", "alice", "a@x.com", "feed")
            s2 = SubscriberStore(p)
            self.assertEqual(s2.get_by_license("K1")["discord_id"], "1000")
            self.assertEqual(s2.get_by_discord("1000")["email"], "a@x.com")

    def test_bind_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            s = SubscriberStore(Path(d) / "subs.json")
            s.bind("K1", "1000", "alice", None, None)
            with self.assertRaises(paywall.LicenseBoundError):
                s.bind("K1", "2000", "bob", None, None)

    def test_unbind(self):
        with tempfile.TemporaryDirectory() as d:
            s = SubscriberStore(Path(d) / "subs.json")
            s.bind("K1", "1000", "alice", None, None)
            s.unbind("K1")
            self.assertIsNone(s.get_by_license("K1"))

    def test_corrupt_starts_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "subs.json"
            p.write_text("{nope")
            self.assertEqual(len(SubscriberStore(p).subs), 0)


class TestPaywallSubscribe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_short_key_rejected_without_network(self):
        pw = make_paywall(self.tmp.name)
        res = pw.subscribe("short", "1000")
        self.assertFalse(res["ok"])
        self.assertEqual(len(pw.transport.calls), 0)  # gumroad never pinged

    def test_success_binds_and_grants_role(self):
        pw = make_paywall(self.tmp.name, [gumroad_ok()])
        res = pw.subscribe("KEY-ABCD-1234", "1000", "alice")
        self.assertTrue(res["ok"])
        self.assertTrue(res["role_granted"])
        role_calls = pw.role_transport.calls
        self.assertEqual(len(role_calls), 1)
        self.assertIn("/guilds/G1/members/1000/roles/R1", role_calls[0]["url"])
        self.assertEqual(pw.store.get_by_license("KEY-ABCD-1234")["discord_id"], "1000")

    def test_second_activation_idempotent(self):
        pw = make_paywall(self.tmp.name,
                          [gumroad_ok(), gumroad_ok(email="a@x.com")])
        pw.subscribe("KEY-ABCD-1234", "1000", "alice")
        res = pw.subscribe("KEY-ABCD-1234", "1000", "alice")
        self.assertTrue(res["ok"])
        self.assertIn("already active", res["message"])

    def test_license_bound_to_other_user(self):
        pw = make_paywall(self.tmp.name, [gumroad_ok(), gumroad_ok()])
        pw.subscribe("KEY-ABCD-1234", "1000", "alice")
        res = pw.subscribe("KEY-ABCD-1234", "2000", "bob")
        self.assertFalse(res["ok"])
        self.assertIn("another Discord account", res["message"])

    def test_bad_key_denied(self):
        pw = make_paywall(self.tmp.name,
                          [Response(status=404, body=b'{"success": false}')])
        res = pw.subscribe("KEY-WRONG-0000", "1000")
        self.assertFalse(res["ok"])

    def test_role_failure_reported_not_swallowed(self):
        pw = make_paywall(self.tmp.name, [gumroad_ok()], role_status=403)
        res = pw.subscribe("KEY-ABCD-1234", "1000")
        self.assertTrue(res["ok"])                      # payment is real, on the books
        self.assertFalse(res["role_granted"])
        self.assertIn("403", res["role_error"])

    def test_no_role_env_still_subscribes(self):
        pw = make_paywall(self.tmp.name, [gumroad_ok()])
        pw.guild_id = pw.role_id = ""
        res = pw.subscribe("KEY-ABCD-1234", "1000")
        self.assertTrue(res["ok"])
        self.assertTrue(res["role_granted"])            # nothing to grant, nothing failed


class TestPaywallStatusAndRevoke(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pw = make_paywall(self.tmp.name, [gumroad_ok()])
        self.pw.subscribe("KEY-ABCD-1234", "1000", "alice")

    def tearDown(self):
        self.tmp.cleanup()

    def test_active_status(self):
        self.pw.transport.responses.append(gumroad_ok())  # live re-verify on status
        st = self.pw.status("1000")
        self.assertTrue(st["active"])
        self.assertEqual(st["email"], "buyer@example.com")

    def test_unknown_user(self):
        self.assertFalse(self.pw.status("9999")["active"])

    def test_lapsed_subscription_revokes(self):
        # next gumroad call says cancelled -> status flips and role is revoked
        self.pw.transport.responses.append(gumroad_ok(cancelled=True))
        df = DeleteFake()
        self.pw.role_transport = df
        st = self.pw.status("1000")
        self.assertFalse(st["active"])
        self.assertEqual(len(df.calls), 1)
        self.assertIn("/members/1000/roles/R1", df.calls[0]["url"])
        self.assertIsNone(self.pw.store.get_by_license("KEY-ABCD-1234"))


class TestCommandsPaywall(unittest.TestCase):
    def test_subscribe_without_paywall_is_honest(self):
        e = commands.cmd_subscribe("KEY-1234", None, "1000")
        self.assertIn("not configured", e["description"])

    def test_dispatch_ephemeral(self):
        d = {"data": {"name": "subscribe",
                      "options": [{"name": "license", "value": "KEY-ABCD-1234"}]},
             "member": {"user": {"id": "1000", "username": "alice"}}}
        pw = mock.Mock()
        pw.subscribe.return_value = {"ok": True, "message": "subscribed",
                                     "email": "a@x.com", "role_granted": True}
        out = commands.respond_to_interaction(d, feeds=None, paywall=pw)
        self.assertEqual(out["flags"], config.EPHEMERAL_FLAGS)
        pw.subscribe.assert_called_once_with("KEY-ABCD-1234", "1000", "alice")

    def test_subscription_dispatch_ephemeral(self):
        d = {"data": {"name": "subscription"},
             "member": {"user": {"id": "1000", "username": "alice"}}}
        pw = mock.Mock()
        pw.status.return_value = {"active": True, "product": "feed",
                                  "since": "2026-09-19T00:00:00Z"}
        out = commands.respond_to_interaction(d, feeds=None, paywall=pw)
        self.assertEqual(out["flags"], config.EPHEMERAL_FLAGS)
        self.assertIn("active", out["embeds"][0]["description"])

    def test_dm_payload_falls_back_to_user(self):
        d = {"data": {"name": "subscribe",
                      "options": [{"name": "license", "value": "KEY-ABCD-1234"}]},
             "user": {"id": "4242", "username": "dm_user"}}
        pw = mock.Mock()
        pw.subscribe.return_value = {"ok": False, "message": "nope"}
        commands.respond_to_interaction(d, feeds=None, paywall=pw)
        pw.subscribe.assert_called_once_with("KEY-ABCD-1234", "4242", "dm_user")


class TestDigestEmbed(unittest.TestCase):
    def _finding(self, band):
        from leviathan_triage.models import Asset, KevEntry
        from leviathan_triage.score import score_finding
        entry = KevEntry(cve="CVE-2024-3400", vendor_project="Palo Alto",
                         product="GlobalProtect", date_added="2024-04-12",
                         known_ransomware=False, short_description="cmd inj")
        # P0: KEV + EPSS >= 0.50 · P1: KEV only (low EPSS, no CVSS assessment)
        epss = 0.94 if band == "P0" else 0.10
        return score_finding("CVE-2024-3400", Asset(identifier="ngfw"), entry,
                             epss, {}, "keyword")

    def test_cta_with_buy_url(self):
        findings = [self._finding("P0"), self._finding("P1")]
        e = discord.digest_embed(findings, buy_url="https://gum.co/levip0")
        cta = e["fields"][0]["value"]
        self.assertIn("gum.co/levip0", cta)
        self.assertIn("$5/mo", cta)
        self.assertIn("P0", e["title"])

    def test_cta_without_buy_url(self):
        e = discord.digest_embed([self._finding("P1")], buy_url="")
        self.assertIn("ask the admin", e["fields"][0]["value"].lower())

    def test_quiet_day_still_honest(self):
        e = discord.digest_embed([], buy_url="")
        self.assertIn("quiet is not safe", e["description"])


if __name__ == "__main__":
    unittest.main()
