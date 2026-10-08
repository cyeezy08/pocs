from leviathan_core.models import Asset
from leviathan_core.feeds.kev import KevEntry
from leviathan_core.match import match_asset_kev


def e(vendor="acme", product="super Server"):
    return KevEntry(cve="CVE-2026-0001", vendor_project=vendor, product=product,
                    date_added="2026-09-01", known_ransomware=False, short_description="")


def test_cpe_exact_match():
    a = Asset(identifier="mail.acme.test", cpe="cpe:2.3:a:acme:super_server:14.3:*:*:*:*:*:*:*",
              vendor="acme", product="super_server")
    assert match_asset_kev(a, e()) == "cpe"


def test_keyword_match_multiword():
    a = Asset(identifier="mail.acme.test", keywords=["super server"], vendor="acme")
    assert match_asset_kev(a, e()) == "keyword"


def test_vendor_disagreement_blocks_match():
    a = Asset(identifier="browser.host.test", keywords=["chrome"], vendor="chromium")
    assert match_asset_kev(a, e(vendor="google", product="chrome")) is None


def test_no_tokens_no_match():
    a = Asset(identifier="random.host.test")
    assert match_asset_kev(a, e()) is None


def test_normalization_underscores_and_case():
    a = Asset(identifier="x", vendor="ACME", product="super-server")
    assert match_asset_kev(a, e()) == "keyword"


def test_partial_product_token_no_match():
    # KEV product "super Server" needs BOTH tokens; "server" alone doesn't match
    a = Asset(identifier="db.host.test", keywords=["server"], vendor="acme")
    assert match_asset_kev(a, e()) is None
