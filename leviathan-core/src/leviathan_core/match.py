"""Matching: KEV vendor/product against the registered asset set.

Two confidence levels, recorded on every finding:
  cpe     - inventory gave an explicit CPE (vendor+product) and it matches
  keyword - normalized product/vendor token overlap

Honest limitation (also stated in README): v0 matching is product-level.
Version-range precision is Phase 3 work; versions are recorded as evidence,
not silently trusted.
"""
from __future__ import annotations

from . import config
from .feeds.kev import KevEntry
from .models import Asset, normalize, tokenize


def match_asset_kev(asset: Asset, entry: KevEntry) -> str | None:
    """Return match confidence ('cpe'|'keyword') or None.

    KEV products are often multi-word ("Exchange Server", "BIG-IP"). We match
    on token overlap: all KEV product tokens must appear in the asset's token
    set (or vice versa for exact short names), plus vendor agreement when the
    asset declares a vendor.
    """
    asset_tokens = asset.match_tokens()
    if not asset_tokens:
        return None

    kev_product_tokens = tokenize(entry.product)
    kev_vendor_tokens = tokenize(entry.vendor_project)

    if not kev_product_tokens:
        return None

    # CPE path: vendor+product token agreement (order-independent, normalized)
    if asset.cpe and asset.vendor and asset.product:
        vendor_tokens = tokenize(asset.vendor)
        prod_tokens = tokenize(asset.product)
        vendor_ok = bool(vendor_tokens and
                         (vendor_tokens <= kev_vendor_tokens or kev_vendor_tokens <= vendor_tokens))
        product_ok = (prod_tokens == kev_product_tokens or normalize(asset.product) in kev_product_tokens)
        if vendor_ok and product_ok:
            return "cpe"

    # Keyword path: every KEV product token must be covered by asset tokens
    if not kev_product_tokens.issubset(asset_tokens):
        return None

    # vendor check: if asset declares vendor and KEV declares vendor, they
    # must agree on at least one token (prevents "chrome" matching "chromium")
    if asset.vendor and kev_vendor_tokens:
        if not (tokenize(asset.vendor) & kev_vendor_tokens):
            return None
    return "keyword"


def match_all(assets: list[Asset], kev: dict[str, KevEntry]) -> list[tuple[str, Asset, KevEntry, str]]:
    """Cross every asset against the KEV catalog. Returns (cve, asset, entry, confidence)."""
    hits: list[tuple[str, Asset, KevEntry, str]] = []
    seen: set[tuple[str, str]] = set()
    for asset in assets:
        for cve, entry in kev.items():
            conf = match_asset_kev(asset, entry)
            if conf and (cve, asset.identifier) not in seen:
                seen.add((cve, asset.identifier))
                hits.append((cve, asset, entry, conf))
    return hits
