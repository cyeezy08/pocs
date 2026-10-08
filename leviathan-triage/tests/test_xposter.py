"""Huginn (X auto-poster) tests - known-answer OAuth signing + flows.

The golden vector is X's own documented example ("Creating a signature"),
so the signer is pinned to the canonical implementation, not to itself.
No test talks to the network.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from leviathan_triage import cli, config, xposter
from leviathan_triage.http import Response
from leviathan_triage.models import Asset, KevEntry
from leviathan_triage.score import score_finding
from leviathan_triage.xposter import (XApiError, compose_post, oauth_header,
                                      oauth_signature, percent_encode,
                                      post_tweet, request_token,
                                      verify_credentials)


CREDS_ENV = {
    config.ENV_X_CONSUMER_KEY: "ck_test",
    config.ENV_X_CONSUMER_SECRET: "cs_test",
    config.ENV_X_ACCESS_TOKEN: "at_test",
    config.ENV_X_ACCESS_SECRET: "as_test",
}


def finding(band="P0", cve="CVE-2026-0001", vendor="Palo Alto",
            product="PAN-OS", epss=0.94, in_kev=True):
    entry = None
    if in_kev:
        entry = KevEntry(cve=cve, vendor_project=vendor, product=product,
                         date_added="2026-09-19", known_ransomware=(band == "P0"),
                         short_description=" exploited")
    # KEV-matched findings are never below P1; P3 only exists off-KEV with low EPSS
    return score_finding(cve, Asset(identifier=f"{vendor} {product}"), entry,
                         epss, {}, "keyword")


class TestSigning(unittest.TestCase):
    def test_percent_encode(self):
        self.assertEqual(percent_encode("Hello Ladies + Gentlemen"), "Hello%20Ladies%20%2B%20Gentlemen")
        self.assertEqual(percent_encode("a/b~c-d.e_f"), "a%2Fb~c-d.e_f")
        self.assertEqual(percent_encode(""), "")

    def test_golden_vector(self):
        # The canonical RFC 5849 / X "creating a signature" example inputs.
        # Expected signature cross-checked against oauthlib 3.3.1 (reference
        # implementation) signing the same form-encoded body - oauthlib emits
        # exactly this value, so the vector is pinned to a verified oracle.
        sig = oauth_signature(
            "POST", "https://api.twitter.com/1.1/statuses/update.json",
            {"status": "Hello Ladies + Gentlemen, a signed OAuth request!",
             "include_entities": "true",
             "oauth_consumer_key": "xvz1evFS4wEEPTGEFPHBog",
             "oauth_nonce": "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
             "oauth_signature_method": "HMAC-SHA1",
             "oauth_timestamp": "1318622958",
             "oauth_token": "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
             "oauth_version": "1.0"},
            "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
            "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE")
        self.assertEqual(sig, "hCtSmYh+iHYCEqBWrE7C7hYmtUk=")

    def test_cross_check_oauthlib_if_present(self):
        try:
            from oauthlib.oauth1 import Client
        except ImportError:
            self.skipTest("oauthlib not installed - golden vector above is the pin")
        import random
        random.seed(2026)
        for i in range(5):
            nonce = f"nonce-{i}-{random.random()}"
            ts = str(1789000000 + i)
            body_params = {"status": f"post {i} - CVE-2026-00{i} 95/100"}
            ours = oauth_header(
                "POST", "https://api.twitter.com/2/tweets", "ck", "cs",
                token="at", token_secret="ats", nonce=nonce, timestamp=ts,
                body_params=body_params)
            c = Client("ck", client_secret="cs", resource_owner_key="at",
                       resource_owner_secret="ats", nonce=nonce, timestamp=ts)
            _, headers, _ = c.sign(
                "https://api.twitter.com/2/tweets", http_method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=list(body_params.items()))
            import re
            import urllib.parse as up
            theirs = re.search(r'oauth_signature="([^"]+)"',
                               headers["Authorization"]).group(1)
            ours_sig = re.search(r'oauth_signature="([^"]+)"', ours).group(1)
            self.assertEqual(up.unquote(ours_sig), up.unquote(theirs))

    def test_header_deterministic_and_sorted(self):
        h1 = oauth_header("POST", "https://api.twitter.com/2/tweets",
                          "ck", "cs", token="at", token_secret="ats",
                          nonce="noncelong", timestamp="1234567890")
        h2 = oauth_header("POST", "https://api.twitter.com/2/tweets",
                          "ck", "cs", token="at", token_secret="ats",
                          nonce="noncelong", timestamp="1234567890")
        self.assertEqual(h1, h2)
        self.assertTrue(h1.startswith("OAuth "))
        self.assertIn('oauth_consumer_key="ck"', h1)
        self.assertIn("oauth_signature=", h1)
        # signature differs when any param changes
        h3 = oauth_header("POST", "https://api.twitter.com/2/tweets",
                          "ck", "cs", token="at", token_secret="ats",
                          nonce="othernonce", timestamp="1234567890")
        self.assertNotEqual(h1, h3)

    def test_json_body_never_signed(self):
        # form body params join the signature; JSON tweets must not
        h = oauth_header("POST", "https://api.twitter.com/2/tweets",
                         "ck", "cs", token="at", token_secret="ats",
                         nonce="n", timestamp="1")
        self.assertNotIn("text", h)


class FakeJsonTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, url, payload, timeout, headers):
        self.calls.append({"url": url, "payload": payload, "headers": headers})
        return self.response


class TestPostFlow(unittest.TestCase):
    def test_post_ok(self):
        fake = FakeJsonTransport(Response(
            status=201, body=json.dumps({"data": {"id": "123", "text": "hi"}}).encode()))
        with mock.patch.dict("os.environ", CREDS_ENV):
            res = post_tweet("hi", transport=fake)
        self.assertEqual(res["id"], "123")
        self.assertEqual(fake.calls[0]["url"], config.X_TWEET_ENDPOINT)
        self.assertEqual(fake.calls[0]["payload"], {"text": "hi"})
        self.assertTrue(fake.calls[0]["headers"]["Authorization"].startswith("OAuth "))

    def test_missing_user_tokens_is_actionable(self):
        env = {k: v for k, v in CREDS_ENV.items() if "ACCESS" not in k}
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(XApiError) as cm:
                post_tweet("hi")
        self.assertIn("developer.x.com", str(cm.exception))

    def test_403_is_actionable(self):
        fake = FakeJsonTransport(Response(
            status=403, body=json.dumps({"detail": "client-not-enabled"}).encode()))
        with mock.patch.dict("os.environ", CREDS_ENV):
            with self.assertRaises(XApiError) as cm:
                post_tweet("hi", transport=fake)
        self.assertIn("403", str(cm.exception))
        self.assertIn("Read+Write", str(cm.exception))

    def test_429_shows_reset(self):
        fake = FakeJsonTransport(Response(status=429, body=b"{}",
                                          headers={"x-rate-limit-reset": "1700000000"}))
        with mock.patch.dict("os.environ", CREDS_ENV):
            with self.assertRaises(XApiError) as cm:
                post_tweet("hi", transport=fake)
        self.assertIn("1700000000", str(cm.exception))

    def test_verify_me(self):
        class GetFake:
            def __call__(self, url, timeout, headers):
                self.url, self.headers = url, headers
                return Response(status=200, body=json.dumps(
                    {"data": {"id": "42", "username": "leviathan"}}).encode())
        gf = GetFake()
        with mock.patch.dict("os.environ", CREDS_ENV):
            me = verify_credentials(transport=gf)
        self.assertEqual(me["username"], "leviathan")
        self.assertIn("/2/users/me", gf.url)

    def test_request_token_probe(self):
        class FormFake:
            def __call__(self, url, payload, timeout, headers):
                self.headers = headers
                return Response(status=200, body=b"oauth_token=REQT&"
                                                 b"oauth_token_secret=REQS&"
                                                 b"oauth_callback_confirmed=true")
        ff = FormFake()
        res = request_token("ck", "cs", transport=ff)
        self.assertTrue(res["confirmed"])
        self.assertEqual(res["oauth_token"], "REQT")
        self.assertIn("oauth", ff.headers["Authorization"])

    def test_request_token_bad_consumer(self):
        fake = FakeJsonTransport(Response(status=401, body=b""))
        with self.assertRaises(XApiError) as cm:
            request_token("ck", "wrong", transport=fake)
        self.assertIn("rejected", str(cm.exception))


class TestCompose(unittest.TestCase):
    def test_none_when_quiet(self):
        # off-KEV + EPSS 0.10 -> 16 points -> P3 noise; Huginn stays grounded
        self.assertIsNone(compose_post([finding("P3", epss=0.10, in_kev=False)]))

    def test_basic_shape_under_280(self):
        text = compose_post([finding("P0"), finding("P1", cve="CVE-2026-0002")],
                            link="https://discord.gg/abc")
        self.assertLessEqual(len(text), 280)
        self.assertIn("KEV watch", text)
        self.assertIn("CVE-2026-0001", text)
        self.assertIn("discord.gg/abc", text)
        self.assertIn("triage yours free", text)

    def test_long_queue_drops_to_fit(self):
        findings = [finding("P0", cve=f"CVE-2026-{i:04d}") for i in range(12)]
        text = compose_post(findings, link="https://discord.gg/abc")
        self.assertLessEqual(len(text), 280)
        self.assertIn("12", text)  # head mentions total hot count

    def test_no_link_still_honest(self):
        text = compose_post([finding("P0")], link="")
        self.assertIn("triage yours free", text)
        self.assertNotIn("None", text)


class TestCliTweet(unittest.TestCase):
    def setUp(self):
        import io
        import os as _os
        self.tmp = tempfile.TemporaryDirectory()
        self.sdir = Path(self.tmp.name) / "state"
        cache = self.sdir / "cache"
        cache.mkdir(parents=True)
        (cache / "kev.json").write_text(json.dumps({
            "source": "test", "fetched_at": 9999999999.0,
            "dateReleased": "2026-09-10",
            "vulnerabilities": [
                {"cve": "CVE-2024-3400", "vendorProject": "Palo Alto",
                 "product": "GlobalProtect", "dateAdded": "2024-04-12",
                 "knownRansomwareCampaignUse": "Known", "shortDescription": "cmd inj"},
            ]}))
        (cache / "epss.csv").write_text(
            "cve,epss,percentile\nCVE-2024-3400,0.94,0.99\n")
        self.assets = Path(self.tmp.name) / "assets.json"
        from leviathan_triage import assets as am
        am.write_starter(self.assets)
        self._io = io

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *argv):
        from contextlib import redirect_stdout
        out = self._io.StringIO()
        code = 0
        with redirect_stdout(out):
            code = cli.main(["--state-dir", str(self.sdir),
                             "--assets", str(self.assets), *argv])
        return code, out.getvalue()

    def test_dry_run_needs_no_credentials(self):
        env = {k: "" for k in CREDS_ENV}  # even empty creds -> dry-run works
        with mock.patch.dict("os.environ", env, clear=True):
            code, out = self.run_cli("tweet", "--dry-run",
                                     "--link", "https://discord.gg/abc")
        self.assertEqual(code, 0)
        self.assertIn("would post", out)
        self.assertIn("CVE-2024-3400", out)

    def test_post_without_creds_exit_3(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            code, _ = self.run_cli("tweet")
        self.assertEqual(code, 3)

    def test_posted_prints_url(self):
        fake = FakeJsonTransport(Response(
            status=201, body=json.dumps({"data": {"id": "777", "text": "x"}}).encode()))
        with mock.patch.dict("os.environ", CREDS_ENV):
            with mock.patch.object(xposter_module(), "post_tweet",
                                   side_effect=lambda t, env=None, transport=None:
                                   {"id": "777", "text": t}):
                code, out = self.run_cli("tweet")
        self.assertEqual(code, 0)
        self.assertIn("x.com/i/status/777", out)


def xposter_module():
    import leviathan_triage.xposter as m
    return m


if __name__ == "__main__":
    unittest.main()
