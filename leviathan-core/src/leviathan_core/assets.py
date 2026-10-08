"""Asset inventory loader with the authorization gate.

Product identity rule (from PROJECT_AUDIT.md): this tool only ever reasons
about customer-owned, explicitly authorized assets. An inventory without a
verbatim attestation is refused - exit code 2. This gate is the difference
between an exposure platform and a gray-zone scanner.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from . import config
from .models import Asset


class InventoryError(ValueError):
    pass


def _parse_cpe(cpe: str) -> tuple[str | None, str | None, str | None]:
    """Extract (vendor, product, version) from a cpe:2.3 string."""
    parts = cpe.split(":")
    # cpe:2.3:part:vendor:product:version:...
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor = parts[3] if parts[3] != "*" else None
        product = parts[4] if parts[4] != "*" else None
        version = parts[5] if parts[5] not in ("*", "-", "") else None
        return vendor, product, version
    raise InventoryError(f"unsupported CPE format (want cpe:2.3): {cpe!r}")


def load_inventory(path: str | Path) -> list[Asset]:
    """Load + validate an inventory YAML. Refuses unattested inventories."""
    p = Path(path)
    if not p.exists():
        raise InventoryError(f"inventory file not found: {p}")
    data = yaml.safe_load(p.read_text())
    if not isinstance(data, dict):
        raise InventoryError("inventory must be a YAML mapping")

    if data.get("attestation") != config.REQUIRED_ATTESTATION:
        raise InventoryError(
            "authorization attestation missing or invalid: inventory must declare "
            f"`attestation: {config.REQUIRED_ATTESTATION}` - you may only register "
            "assets you own or are contracted to assess."
        )
    if not data.get("owner_contact"):
        raise InventoryError("inventory must declare `owner_contact` (email or handle)")

    raw_assets = data.get("assets") or []
    if not isinstance(raw_assets, list) or not raw_assets:
        raise InventoryError("inventory must contain a non-empty `assets` list")

    assets: list[Asset] = []
    for i, a in enumerate(raw_assets):
        if not isinstance(a, dict) or not a.get("identifier"):
            raise InventoryError(f"assets[{i}] needs an `identifier`")
        vendor = product = version = None
        cpe = a.get("cpe")
        if cpe:
            vendor, product, version = _parse_cpe(cpe)
        assets.append(
            Asset(
                identifier=str(a["identifier"]),
                vendor=(a.get("vendor") or vendor),
                product=(a.get("product") or product),
                version=(a.get("version") or version),
                cpe=cpe,
                keywords=[str(k) for k in (a.get("keywords") or [])],
                source=a.get("source", "manual"),
            )
        )
    return assets


def inventory_from_httpx(httpx_txt: str, domain: str) -> dict:
    """Build an inventory skeleton from ProjectDiscovery httpx output
    (one live host per line). Eat-from, not compete-with."""
    hosts = [h.strip() for h in httpx_txt.splitlines() if h.strip()]
    if not hosts:
        raise InventoryError("no hosts found in httpx output")
    return {
        "attestation": config.REQUIRED_ATTESTATION,
        "owner_contact": f"operator@{domain}",
        "assets": [
            {"identifier": h, "keywords": [domain], "source": "httpx"} for h in hosts
        ],
    }


def gate_or_die(assets: list[Asset]) -> None:
    """Final guard: passive tool refusing to run on nothing is fine; running
    on an empty-token set is a bug, not a mode."""
    if not assets:
        print("refusing: zero assets loaded", file=sys.stderr)
        sys.exit(2)
