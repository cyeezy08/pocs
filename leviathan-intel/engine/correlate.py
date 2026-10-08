"""CPE-based correlation: match a discovered asset to CVEs that affect it.

NVD publishes affected-product configurations as CPE strings, e.g.
    cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
An asset discovered via banner/product fingerprinting carries its own CPE.
Correlation = (vendor, product) equality; version handled conservatively:
we only claim a match when NVD lists no specific version (wildcard, meaning
"any version of this product") or the exact same version string.

Range math (<=, <, version ranges) is deliberately NOT attempted here -
false-positive version math is worse than missing a range match; ranges are
handled later by the enrichment step with proper CPE range parsing (backlog).
"""
from __future__ import annotations


def parse_cpe(cpe: str | None) -> dict | None:
    """Parse cpe:2.3:<part>:<vendor>:<product>:<version>:... into a dict."""
    if not cpe:
        return None
    parts = cpe.strip().split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return {
        "part": parts[2],
        "vendor": parts[3].strip().lower(),
        "product": parts[4].strip().lower(),
        "version": parts[5].strip() if len(parts) > 5 else "",
    }


def _is_wildcard(version: str) -> bool:
    return version in ("", "*", "-")


def asset_matches_cve(asset_cpe: str, cve_cpe_matches: list[str]) -> tuple[bool, str]:
    """Return (matched, reason). cve_cpe_matches = CPE strings from NVD config."""
    asset = parse_cpe(asset_cpe)
    if not asset:
        return False, "asset CPE unparsable"
    if not asset["vendor"] or not asset["product"]:
        return False, "asset CPE missing vendor/product"

    for raw in cve_cpe_matches or []:
        listed = parse_cpe(raw)
        if not listed:
            continue
        if listed["part"] != asset["part"]:
            continue
        if listed["vendor"] != asset["vendor"] or listed["product"] != asset["product"]:
            continue
        if _is_wildcard(listed["version"]):
            return True, (
                f"product match {asset['vendor']}:{asset['product']} "
                f"(NVD lists any version; asset version: {asset['version'] or 'unknown'})"
            )
        if listed["version"] == asset["version"]:
            return True, (
                f"exact version match {asset['vendor']}:{asset['product']}"
                f":{asset['version']}"
            )
    return False, ""
