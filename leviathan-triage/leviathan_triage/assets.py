"""Asset inventory loaders - you declare software; the bot declares nothing.

Accepted inputs:
  assets.json  [{"identifier": "edge-fw", "vendor": "ivanti",
                 "product": "connect secure", "version": "9.x",
                 "keywords": ["connect secure"], "cpe": "cpe:2.3:..."} , ...]
               (also accepts {"assets": [...]})
  httpx -json  one JSON object per line: {"host": ..., "tech": [...]}
               -> keywords from detected tech (identifier = host)
  plain lines  "vendor/product" or "Product Name" or "Product Name # comment"

Validation is loud: a typo in your inventory is worse than no inventory.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Asset


class AssetError(ValueError):
    pass


def _asset_from_obj(obj: dict, idx: int, source: str = "manual") -> Asset:
    if not isinstance(obj, dict):
        raise AssetError(f"entry {idx}: expected an object, got {type(obj).__name__}")
    identifier = str(obj.get("identifier") or obj.get("host") or "").strip()
    product = (obj.get("product") or "").strip() or None
    if not identifier and not product:
        raise AssetError(f"entry {idx}: needs at least 'identifier' or 'product'")
    if not identifier:
        identifier = product
    kw = obj.get("keywords") or []
    if isinstance(kw, str):
        kw = [kw]
    return Asset(
        identifier=identifier,
        vendor=(obj.get("vendor") or "").strip() or None,
        product=product,
        version=(obj.get("version") or "").strip() or None,
        cpe=(obj.get("cpe") or "").strip() or None,
        keywords=[str(k) for k in kw],
        source=obj.get("source") or source,
    )


def from_json(path: Path) -> list:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise AssetError(f"{path}: invalid JSON - {e}") from e
    if isinstance(doc, dict):
        doc = doc.get("assets")
        if doc is None:
            raise AssetError(f"{path}: JSON object must contain an 'assets' array")
    if not isinstance(doc, list):
        raise AssetError(f"{path}: expected a top-level array")
    return [_asset_from_obj(o, i) for i, o in enumerate(doc)]


def from_httpx(path: Path) -> list:
    """httpx -json lines -> assets keyed by host, keywords from detected tech."""
    out: list = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            raise AssetError(f"{path}: line {n + 1} is not JSON (run httpx with -json)")
        host = str(rec.get("host") or rec.get("url") or "").strip()
        if not host:
            continue
        tech = rec.get("tech") or rec.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]
        out.append(Asset(identifier=host, keywords=[str(t) for t in tech],
                         source="httpx"))
    if not out:
        raise AssetError(f"{path}: no usable httpx records")
    return out


def from_lines(path: Path) -> list:
    out: list = []
    for n, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines()):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "/" in line:
            vendor, _, product = line.partition("/")
            out.append(Asset(identifier=line, vendor=vendor.strip() or None,
                             product=product.strip() or None))
        else:
            out.append(Asset(identifier=line, keywords=[line]))
    if not out:
        raise AssetError(f"{path}: no assets found")
    return out


def load(path) -> list:
    """Auto-detect format by extension/content. .json -> json, .jsonl -> httpx,
    otherwise try json then lines."""
    p = Path(path)
    if not p.exists():
        raise AssetError(f"{p}: file not found (run 'init-assets' for a starter)")
    if p.suffix == ".jsonl":
        return from_httpx(p)
    if p.suffix == ".json":
        return from_json(p)
    text = p.read_text(encoding="utf-8")
    if text.lstrip().startswith(("[", "{")):
        return from_json(p)
    return from_lines(p)


def write_starter(path) -> list:
    """Write the demo inventory (the products on leviathan.ac's own live feed)
    and return the parsed assets."""
    starter = {
        "assets": [
            {"identifier": "vpn-edge", "vendor": "ivanti", "product": "connect secure",
             "keywords": ["ivanti connect secure", "ive"]},
            {"identifier": "mdm", "vendor": "ivanti", "product": "epmm",
             "keywords": ["ivanti epmm", "mobileiron"]},
            {"identifier": "ci", "vendor": "jenkins", "product": "jenkins",
             "version": "2.441"},
            {"identifier": "ngfw", "vendor": "palo alto", "product": "globalprotect",
             "keywords": ["pan-os"]},
            {"identifier": "web-proxy", "vendor": "sophos", "product": "web appliance",
             "keywords": ["sophos web appliance"]},
            {"identifier": "itsm", "vendor": "servicenow", "product": "servicenow"},
        ]
    }
    Path(path).write_text(json.dumps(starter, indent=2) + "\n", encoding="utf-8")
    return from_json(Path(path))
