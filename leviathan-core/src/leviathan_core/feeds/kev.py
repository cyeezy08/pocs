"""CISA KEV feed - with a source chain, because the internet is hostile.

Sources, in order:
  1. cisa.gov official JSON (preferred; some datacenter IPs get 403'd)
  2. kevin.gtfkd.com mirror (paginated, KEV-shaped, community-run)

The cache records which source won, and the report shows it. Silent source
drift is how numbers stop meaning things.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import requests

from .. import config

KEV_SOURCES = {
    "cisa.gov": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "mirror:kevin.gtfkd.com": "https://kevin.gtfkd.com/kev",
}


@dataclass
class KevEntry:
    cve: str
    vendor_project: str
    product: str
    date_added: str
    known_ransomware: bool
    short_description: str


def _fetch_cisa(session: requests.Session) -> dict:
    r = session.get(KEV_SOURCES["cisa.gov"], timeout=60)
    r.raise_for_status()
    return r.json()


def _fetch_mirror(session: requests.Session) -> dict:
    vulnerabilities: list[dict] = []
    page = 1
    total_pages = 1
    while page <= total_pages:
        r = session.get(KEV_SOURCES["mirror:kevin.gtfkd.com"],
                        params={"page": page}, timeout=60)
        r.raise_for_status()
        doc = r.json()
        total_pages = int(doc.get("total_pages", 1))
        vulnerabilities.extend(doc.get("vulnerabilities", []))
        page += 1
        if page <= total_pages:
            time.sleep(0.4)
    return {"vulnerabilities": vulnerabilities,
            "dateReleased": "mirror (per-entry dateAdded preserved)"}


def sync(cache_dir: Path) -> dict[str, KevEntry]:
    """Fetch KEV via the source chain (or read cache) -> {cve: KevEntry}.
    The winning source is recorded inside the cache file and surfaced by
    catalog_date()."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "kev.json"
    if cache_file.exists():
        doc = json.loads(cache_file.read_text())
    else:
        doc, source = {}, None
        errors: list[str] = []
        with requests.Session() as s:
            s.headers.update({"User-Agent": config.TOOL})
            for name, fetch in (("cisa.gov", _fetch_cisa),
                                ("mirror:kevin.gtfkd.com", _fetch_mirror)):
                try:
                    doc = fetch(s)
                    source = name
                    break
                except Exception as e:  # noqa: BLE001 - feed chain must survive any one failure
                    errors.append(f"{name}: {type(e).__name__} {str(e)[:80]}")
            if doc is None or source is None:
                raise RuntimeError("all KEV sources failed: " + " | ".join(errors))
        doc["_source"] = source
        doc["_fetched_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cache_file.write_text(json.dumps(doc))

    out: dict[str, KevEntry] = {}
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cveID", "")
        if not cve:
            continue
        out[cve] = KevEntry(
            cve=cve,
            vendor_project=str(v.get("vendorProject", "")).lower(),
            product=str(v.get("product", "")).lower(),
            date_added=v.get("dateAdded", ""),
            known_ransomware=v.get("knownRansomwareCampaignUse", "") == "Known",
            short_description=v.get("shortDescription", ""),
        )
    return out


def catalog_date(cache_dir: Path) -> str:
    f = cache_dir / "kev.json"
    if not f.exists():
        return "not synced"
    doc = json.loads(f.read_text())
    date = doc.get("dateReleased")
    src = doc.get("_source", "unknown")
    fetched = doc.get("_fetched_at", "?")
    return f"{date or 'mirror'} [source: {src}, fetched: {fetched}]"
