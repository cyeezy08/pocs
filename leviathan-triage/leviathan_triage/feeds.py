"""Public exploit-intel feeds with provenance, TTL caches, and honest failure.

KEV source chain (because the internet is hostile):
  1. cisa.gov official JSON (preferred; some datacenter IPs get 403'd)
  2. kevin.gtfkd.com mirror (paginated, KEV-shaped, community-run)

The winning source is recorded in the cache file and surfaced everywhere.
Silent source drift is how numbers stop meaning things - not here.

EPSS: FIRST's bulk daily CSV (gzipped). ~373k rows; streamed, cached on disk.
NVD : per-CVE on demand (--deep only), per-CVE disk cache, graceful
      degradation - a failed enrichment contributes 0 points and says why.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import time
from pathlib import Path
from typing import Callable, Optional

from . import config
from .http import http_get, TransportError
from .models import KevEntry


def _kev_from_doc(doc: dict, source: str) -> dict:
    entries: dict = {}
    for v in doc.get("vulnerabilities", []):
        # CISA official and the community mirror differ on the CVE key:
        # accept both schemas so one upstream rename can't zero the queue.
        cve = (v.get("cve") or v.get("cveID") or "").strip()
        if not cve:
            continue
        entries[cve] = KevEntry(
            cve=cve,
            vendor_project=(v.get("vendorProject") or "").strip(),
            product=(v.get("product") or "").strip(),
            date_added=(v.get("dateAdded") or "").strip(),
            known_ransomware=(v.get("knownRansomwareCampaignUse") == "Known"),
            short_description=(v.get("shortDescription") or "").strip(),
        )
    return {"source": source, "entries": entries,
            "date_released": doc.get("dateReleased") or ""}


class Feeds:
    def __init__(self, cache_dir: Path,
                 transport: Optional[Callable] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 now: Callable[[], float] = time.time):
        self.cache_dir = Path(cache_dir)
        self.transport = transport
        self.sleep = sleep
        self.now = now
        self._kev_cache: Optional[dict] = None
        self._epss_cache: Optional[dict] = None

    # ------------------------------------------------------------------ KEV
    def _fetch_cisa(self) -> dict:
        r = http_get(config.FEEDS["kev"], timeout=60, transport=self.transport)
        if r.status != 200:
            raise TransportError(f"cisa.gov HTTP {r.status}")
        return r.json()

    def _fetch_mirror(self) -> dict:
        vulns: list = []
        page, total_pages = 1, 1
        while page <= total_pages:
            r = http_get(f"{config.FEEDS['kev_mirror']}?page={page}",
                         timeout=60, transport=self.transport)
            if r.status != 200:
                raise TransportError(f"mirror HTTP {r.status}")
            doc = r.json()
            total_pages = min(int(doc.get("total_pages", 1)), 200)  # sanity cap
            vulns.extend(doc.get("vulnerabilities", []))
            page += 1
            if page <= total_pages:
                self.sleep(0.4)
        return {"vulnerabilities": vulns,
                "dateReleased": "mirror (per-entry dateAdded preserved)"}

    def kev(self, force: bool = False,
            max_age: Optional[float] = None) -> dict:
        """-> {cve: KevEntry}. Cache-first; source chain on miss/expiry."""
        if self._kev_cache is not None and not force:
            return self._kev_cache["entries"]
        max_age = config.KEV_TTL_SECONDS if max_age is None else max_age
        cf = self.cache_dir / "kev.json"
        if not force and cf.exists():
            doc = json.loads(cf.read_text(encoding="utf-8"))
            age = self.now() - float(doc.get("fetched_at", 0))
            if age <= max_age:
                parsed = _kev_from_doc(doc, doc.get("source", "cache"))
                parsed["fetched_at"] = doc.get("fetched_at", 0)
                self._kev_cache = parsed
                return parsed["entries"]
        errors: list = []
        for name, fetch in (("cisa.gov", self._fetch_cisa),
                            ("mirror:kevin.gtfkd.com", self._fetch_mirror)):
            try:
                doc = fetch()
                parsed = _kev_from_doc(doc, name)
                if not parsed["entries"]:
                    # HTTP 200 with zero parseable entries is a FAILED source,
                    # not an empty catalog. Never cache an empty queue.
                    raise TransportError(f"{name}: 200 OK but 0 parseable entries "
                                         "(schema changed?)")
                parsed["fetched_at"] = self.now()
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                cf.write_text(json.dumps({
                    "source": name,
                    "fetched_at": parsed["fetched_at"],
                    "dateReleased": doc.get("dateReleased", ""),
                    "vulnerabilities": doc.get("vulnerabilities", []),
                }, ensure_ascii=False), encoding="utf-8")
                self._kev_cache = parsed
                return parsed["entries"]
            except (TransportError, ValueError) as e:
                errors.append(f"{name}: {e}")
        raise TransportError("all KEV sources failed - " + "; ".join(errors))

    def kev_source(self) -> str:
        if self._kev_cache:
            return self._kev_cache["source"]
        cf = self.cache_dir / "kev.json"
        if cf.exists():
            doc = json.loads(cf.read_text(encoding="utf-8"))
            return f"{doc.get('source', 'cache')} (cached {time.strftime('%Y-%m-%d %H:%M', time.gmtime(doc.get('fetched_at', 0)))} UTC)"
        return "not synced"

    def kev_newest(self, limit: int = 10) -> list:
        entries = sorted(self.kev().values(),
                         key=lambda e: e.date_added, reverse=True)
        return entries[:limit]

    # ----------------------------------------------------------------- EPSS
    @staticmethod
    def _parse_epss(text: str) -> dict:
        out: dict = {}
        lines = text.splitlines()
        header_idx = next((i for i, l in enumerate(lines)
                           if l.startswith("cve,")), None)
        if header_idx is None:
            return out
        reader = csv.DictReader(io.StringIO("\n".join(lines[header_idx:])))
        for row in reader:
            cve = (row.get("cve") or "").strip()
            score = (row.get("epss") or "").strip()
            if cve.startswith("CVE-") and score:
                try:
                    out[cve] = float(score)
                except ValueError:
                    continue
        return out

    def epss(self, force: bool = False,
             max_age: Optional[float] = None) -> dict:
        """-> {cve: probability}. Bulk daily CSV, cached decompressed."""
        if self._epss_cache is not None and not force:
            return self._epss_cache
        max_age = config.EPSS_TTL_SECONDS if max_age is None else max_age
        cf = self.cache_dir / "epss.csv"
        if not force and cf.exists():
            age = self.now() - cf.stat().st_mtime
            if age <= max_age:
                self._epss_cache = self._parse_epss(
                    cf.read_text(encoding="utf-8", errors="replace"))
                return self._epss_cache
        r = http_get(config.FEEDS["epss"], timeout=180, transport=self.transport)
        if r.status != 200:
            raise TransportError(f"EPSS HTTP {r.status}")
        text = gzip.decompress(r.body).decode("utf-8", errors="replace")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        cf.write_text(text, encoding="utf-8")
        self._epss_cache = self._parse_epss(text)
        return self._epss_cache

    def epss_model_date(self) -> str:
        cf = self.cache_dir / "epss.csv"
        if cf.exists():
            first = cf.read_text(encoding="utf-8", errors="replace").splitlines()[0]
            return first.lstrip("# ").strip() or "unknown"
        return "not synced"

    # ------------------------------------------------------------------ NVD
    def nvd_one(self, cve: str, api_key: str = "") -> dict:
        """Per-CVE enrichment -> {cvss, cvss_version, title, refs[], error?}.

        Cached per CVE on disk forever (CVE base scores do not rotate).
        Any failure degrades to {'error': ...} - scoring adds 0 and says why.
        """
        cdir = self.cache_dir / "nvd"
        cfile = cdir / f"{cve}.json"
        if cfile.exists():
            return json.loads(cfile.read_text(encoding="utf-8"))
        url = f"{config.FEEDS['nvd']}?cveId={cve}"
        headers = {"apiKey": api_key} if api_key else {}
        r = http_get(url, timeout=60, headers=headers, transport=self.transport)
        if r.status != 200:
            return {"error": f"NVD HTTP {r.status}"}
        try:
            item = r.json()["vulnerabilities"][0]["cve"]
        except (KeyError, IndexError, ValueError):
            return {"error": "NVD returned no record for " + cve}
        out = {"cvss": None, "cvss_version": "", "title": "", "refs": []}
        containers = item.get("containers", {})
        # cna first, then adp entries (NVD sometimes puts scores in adp)
        holders = [containers.get("cna") or {}] + list(containers.get("adp") or [])
        cvss = None
        for h in holders:
            metrics = h.get("metrics") or {}
            for key in ("cvssV3_1", "cvssV3_0"):
                if cvss is None and key in metrics:
                    data = metrics[key][0]
                    cd = data.get("cvssData") or {}
                    if "baseScore" in cd:
                        cvss = (float(cd["baseScore"]), cd.get("baseSeverity", ""))
                    elif "baseScore" in data:  # rare adp flat variant
                        cvss = (float(data["baseScore"]), "")
                    break
        if cvss:
            out["cvss"], out["cvss_version"] = cvss[0], cvss[1]
        desc = (containers.get("cna") or {}).get("descriptions") or []
        if desc:
            out["title"] = (desc[0].get("value") or "")[:280]
        refs = []
        for ref in (containers.get("cna") or {}).get("references") or []:
            u = ref.get("url") or ""
            if u:
                refs.append(u)
        out["refs"] = refs
        cdir.mkdir(parents=True, exist_ok=True)
        cfile.write_text(json.dumps(out), encoding="utf-8")
        return out

    def nvd_batch(self, cves: list, api_key: str = "",
                  delay: Optional[float] = None) -> dict:
        """Polite sequential enrichment. -> {cve: nvd_dict_or_error}."""
        out: dict = {}
        pause = config.NVD_DELAY_SECONDS_NO_KEY if delay is None else delay
        first = True
        for cve in sorted(set(cves)):
            if not first and pause:
                self.sleep(pause)
            first = False
            try:
                out[cve] = self.nvd_one(cve, api_key=api_key)
            except (TransportError, ValueError) as e:
                out[cve] = {"error": str(e)}
        return out
