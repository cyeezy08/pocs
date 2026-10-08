"""NVD CVE 2.0 API - on-demand enrichment for MATCHED CVEs only (cached).

We never crawl NVD wholesale: matched set is small, so keyless rate limits
are survivable. Graceful degradation is explicit: a failed fetch yields
cvss=None and an honest reason, never a silent zero.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests

from .. import config

_session = requests.Session()
_session.headers.update({"User-Agent": config.TOOL})
_api_key = os.environ.get("NVD_API_KEY")
if _api_key:
    _session.headers.update({"apiKey": _api_key})


def _delay() -> float:
    return 0.6 if _api_key else config.NVD_DELAY_SECONDS_NO_KEY


def enrich_batch(cves: list[str], cache_dir: Path) -> dict[str, dict]:
    """Fetch CVSS base + references for the given CVEs. Returns
    {cve: {"cvss": float|None, "cvss_version": str, "refs": [str], "title": str}}"""
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "nvd_enrichment.json"
    cache: dict[str, dict] = {}
    if cache_file.exists():
        cache = json.loads(cache_file.read_text())

    todo = [c for c in cves if c not in cache]
    for i, cve in enumerate(todo):
        try:
            r = _session.get(config.FEEDS["nvd"], params={"cveId": cve}, timeout=30)
            if r.status_code == 403:
                cache[cve] = {"cvss": None, "cvss_version": "", "refs": [],
                              "title": "", "error": "rate-limited (set NVD_API_KEY)"}
            else:
                r.raise_for_status()
                cache[cve] = _parse(r.json())
        except requests.RequestException as e:
            cache[cve] = {"cvss": None, "cvss_version": "", "refs": [],
                          "title": "", "error": str(e)[:120]}
        if i < len(todo) - 1:
            time.sleep(_delay())
        # persist incrementally so a long run is resumable
        cache_file.write_text(json.dumps(cache))
    return cache


def _parse(doc: dict) -> dict:
    out = {"cvss": None, "cvss_version": "", "refs": [], "title": ""}
    vulns = doc.get("vulnerabilities") or []
    if not vulns:
        return out
    cve_item = vulns[0].get("cve", {})
    out["title"] = (cve_item.get("descriptions") or [{}])[0].get("value", "")[:200]
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            m = metrics[key][0]["cvssData"]
            out["cvss"] = float(m.get("baseScore"))
            out["cvss_version"] = m.get("baseSeverity", key)
            break
    for r in cve_item.get("references", []):
        tag = (r.get("sourceIdentifier") or "") + " " + r.get("url", "")
        out["refs"].append(r.get("url", ""))
        _ = tag
    return out
