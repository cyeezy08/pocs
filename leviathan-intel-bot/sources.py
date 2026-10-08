#!/usr/bin/env python3
"""
sources.py - keyless threat-intel source clients for the Leviathan bot.

Design rule
-----------
Prefer sources that need NO API key. A bot that scales to many users cannot
ride on one academic Shodan key, and a key that leaks is a key that dies. As
of writing, everything below is free and keyless:

    InternetDB (Shodan)     https://internetdb.shodan.io/<ip>     no key
    NVD 2.0                 https://services.nvd.nist.gov/...     no key
    EPSS (FIRST.org)        https://api.first.org/data/v1/epss    no key
    CISA KEV                cisa.gov .../kev.json                 no key
    Exploit-DB RSS          exploit-db.com/rss.xml                no key

MalwareBazaar moved to requiring an Auth-Key, so hash lookup degrades to
"unavailable" with a clear message unless ABUSECH_AUTH_KEY is set. Better an
honest gap than a feature that silently fails.

Every function returns a dict and never raises for a network problem: a bot
that crashes on one bad source is worse than one that says "source down".

Attribution: Shodan data is attributed wherever it is displayed, per their
billing FAQ ("you can integrate the API in your products as long as the data
is attributed to Shodan").
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

UA = "LeviathanBot/0.1 (+https://github.com/leviathan-offsec)"
TIMEOUT = 25
CACHE_TTL = 900  # seconds; the bot is read-mostly and these feeds change slowly

_cache: dict[str, tuple[float, object]] = {}


def _cached(key: str, fn):
    now = time.time()
    hit = _cache.get(key)
    if hit and now - hit[0] < CACHE_TTL:
        return hit[1]
    val = fn()
    _cache[key] = (now, val)
    return val


def _get(url: str, headers: dict | None = None, data: bytes | None = None,
         method: str | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()


# ---------------------------------------------------------------------------
# InternetDB - the nrich backend. Keyless, fast, one IP at a time.
# ---------------------------------------------------------------------------
def internetdb(ip: str) -> dict:
    """Passive host enrichment. Read-only: queries Shodan's index, not the host."""
    ip = ip.strip()
    if not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return {"error": "not an IP address"}

    def fetch():
        code, body = _get(f"https://internetdb.shodan.io/{ip}")
        if code == 404:
            return {"ip": ip, "found": False,
                    "note": "no record in Shodan's index"}
        if code != 200:
            return {"error": f"internetdb HTTP {code}"}
        try:
            d = json.loads(body)
        except ValueError:
            return {"error": "internetdb returned non-JSON"}
        d["found"] = True
        d["attribution"] = "Shodan InternetDB"
        return d

    return _cached(f"idb:{ip}", fetch)


# ---------------------------------------------------------------------------
# NVD - CVE detail. Keyless but rate-limited; cache aggressively.
# ---------------------------------------------------------------------------
def nvd(cve_id: str) -> dict:
    cve_id = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return {"error": "not a CVE id (expected CVE-YYYY-NNNN)"}

    def fetch():
        code, body = _get("https://services.nvd.nist.gov/rest/json/cves/2.0"
                          f"?cveId={urllib.parse.quote(cve_id)}")
        if code != 200:
            return {"error": f"NVD HTTP {code}"}
        try:
            d = json.loads(body)
        except ValueError:
            return {"error": "NVD returned non-JSON"}
        vulns = d.get("vulnerabilities", [])
        if not vulns:
            return {"id": cve_id, "found": False}
        c = vulns[0]["cve"]
        desc = next((x["value"] for x in c.get("descriptions", [])
                     if x.get("lang") == "en"), "")
        out = {
            "id": c["id"], "found": True,
            "published": c.get("published", "")[:10],
            "status": c.get("vulnStatus", ""),
            "description": desc,
            "cvss": None, "severity": None, "vector": None,
        }
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30",
                    "cvssMetricV2"):
            m = c.get("metrics", {}).get(key)
            if m:
                cd = m[0].get("cvssData", {})
                out["cvss"] = cd.get("baseScore")
                out["severity"] = cd.get("baseSeverity") or m[0].get("baseSeverity")
                out["vector"] = cd.get("vectorString")
                break
        return out

    return _cached(f"nvd:{cve_id}", fetch)


# ---------------------------------------------------------------------------
# EPSS - probability of exploitation in the next 30 days.
# ---------------------------------------------------------------------------
def epss(cve_id: str) -> dict:
    cve_id = cve_id.strip().upper()

    def fetch():
        code, body = _get(f"https://api.first.org/data/v1/epss?cve={cve_id}")
        if code != 200:
            return {"error": f"EPSS HTTP {code}"}
        try:
            d = json.loads(body)
        except ValueError:
            return {"error": "EPSS returned non-JSON"}
        rows = d.get("data", [])
        if not rows:
            return {"id": cve_id, "found": False}
        r = rows[0]
        return {
            "id": cve_id, "found": True,
            "epss": float(r["epss"]),
            "percentile": float(r["percentile"]),
            "date": r.get("date"),
            "attribution": "EPSS (FIRST.org)",
        }

    return _cached(f"epss:{cve_id}", fetch)


# ---------------------------------------------------------------------------
# CISA KEV - has it actually been exploited in the wild?
# ---------------------------------------------------------------------------
def kev(cve_id: str | None = None) -> dict:
    """Whole-catalog lookup. Cached once and reused, since the feed is ~1.7MB."""
    def fetch_all():
        code, body = _get("https://www.cisa.gov/sites/default/files/feeds/"
                          "known_exploited_vulnerabilities.json")
        if code != 200:
            return {"error": f"KEV HTTP {code}"}
        try:
            return json.loads(body)
        except ValueError:
            return {"error": "KEV returned non-JSON"}

    cat = _cached("kev:all", fetch_all)
    if "error" in cat:
        return cat
    if cve_id is None:
        return {"count": cat.get("count"), "catalogVersion": cat.get("catalogVersion")}
    cid = cve_id.strip().upper()
    for v in cat.get("vulnerabilities", []):
        if v.get("cveID", "").upper() == cid:
            return {"id": cid, "found": True, "entry": v,
                    "attribution": "CISA KEV"}
    return {"id": cid, "found": False}


def kev_vendor(vendor: str) -> dict:
    """Every KEV entry for a vendor. This is how 'is it being exploited?' is
    answered at vendor scale rather than one CVE at a time."""
    cat = _cached("kev:all", lambda: json.loads(
        _get("https://www.cisa.gov/sites/default/files/feeds/"
             "known_exploited_vulnerabilities.json")[1]))
    if "error" in cat:
        return cat
    v = vendor.lower()
    hits = [x for x in cat.get("vulnerabilities", [])
            if v in (x.get("vendorProject", "") + " " + x.get("product", "")).lower()]
    return {"vendor": vendor, "count": len(hits), "entries": hits,
            "attribution": "CISA KEV"}


# ---------------------------------------------------------------------------
# Exploit-DB - newest public exploits (RSS, keyless).
# ---------------------------------------------------------------------------
def exploitdb_latest(limit: int = 10) -> dict:
    def fetch():
        code, body = _get("https://www.exploit-db.com/rss.xml")
        if code != 200:
            return {"error": f"exploit-db HTTP {code}"}
        try:
            root = ET.fromstring(body)
        except ET.ParseError as e:
            return {"error": f"exploit-db RSS parse: {e}"}
        items = []
        for it in root.iter("item"):
            items.append({
                "title": (it.findtext("title") or "").strip(),
                "link": (it.findtext("link") or "").strip(),
                "date": (it.findtext("pubDate") or "").strip(),
            })
        return {"items": items, "attribution": "Exploit-DB"}

    d = _cached("edb:latest", fetch)
    if "error" in d:
        return d
    return {"items": d["items"][:limit], "total": len(d["items"]),
            "attribution": "Exploit-DB"}


# ---------------------------------------------------------------------------
# Hash lookup - MalwareBazaar now needs an Auth-Key, so this degrades honestly.
# ---------------------------------------------------------------------------
def hash_lookup(h: str) -> dict:
    h = h.strip().lower()
    if not re.match(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", h):
        return {"error": "not an md5/sha1/sha256 hex digest"}
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        return {
            "error": "hash lookup needs ABUSECH_AUTH_KEY",
            "note": "abuse.ch moved to authenticated lookups. Set the env var to "
                    "enable this button; the rest of the bot needs no keys.",
            "hash": h,
        }
    code, body = _get("https://mb-api.abuse.ch/api/v1/",
                      data=urllib.parse.urlencode(
                          {"query": "get_info", "hash": h}).encode(),
                      headers={"Auth-Key": key},
                      method="POST")
    if code != 200:
        return {"error": f"malwarebazaar HTTP {code}"}
    try:
        d = json.loads(body)
    except ValueError:
        return {"error": "malwarebazaar returned non-JSON"}
    d["hash"] = h
    d["attribution"] = "abuse.ch MalwareBazaar"
    return d


# ---------------------------------------------------------------------------
# The flagship: a CVE intel bundle. This is what the bot's headline button does.
# ---------------------------------------------------------------------------
def cve_intel(cve_id: str) -> dict:
    """NVD + EPSS + KEV in one call, with an exploitation verdict.

    The verdict is the point. A CVSS score alone says how bad it would be;
    these three together say how bad it IS, which is the question a responder
    actually has.
    """
    n = nvd(cve_id)
    if "error" in n:
        return n
    if not n.get("found"):
        return {"id": cve_id, "found": False}
    e = epss(cve_id)
    k = kev(cve_id)
    n["epss"] = e if e.get("found") else None
    n["kev"] = k.get("entry") if k.get("found") else None

    if k.get("found"):
        n["verdict"] = "EXPLOITED IN THE WILD (CISA KEV)"
    elif e.get("found") and e.get("epss", 0) >= 0.5:
        n["verdict"] = "high exploitation probability"
    elif e.get("found"):
        n["verdict"] = "elevated exploitation probability"
    else:
        n["verdict"] = "no exploitation signal"
    return n


if __name__ == "__main__":
    # Self-test against the live sources. Every call here is read-only and
    # keyless, so this doubles as a check that the bot's free tier still works.
    import sys

    print("=== InternetDB (keyless) ===")
    r = internetdb("8.8.8.8")
    print("  ", {k: r.get(k) for k in ("ip", "found", "ports", "tags")})

    print("\n=== NVD + EPSS + KEV bundle (keyless) ===")
    for cve in ("CVE-2021-33044", "CVE-2024-3400"):
        r = cve_intel(cve)
        if r.get("found"):
            print(f"  {r['id']}  CVSS {r.get('cvss')}  {r.get('severity')}")
            print(f"    verdict : {r.get('verdict')}")
            if r.get("kev"):
                print(f"    KEV     : added {r['kev'].get('dateAdded')} "
                      f"({r['kev'].get('vulnerabilityName','')[:60]})")
            if r.get("epss"):
                print(f"    EPSS    : {r['epss']['epss']:.5f} "
                      f"({r['epss']['percentile']*100:.2f}th pct)")
        else:
            print(f"  {cve}: {r.get('error') or 'not found'}")

    print("\n=== KEV vendor sweep ===")
    r = kev_vendor("Dahua")
    print(f"  Dahua KEV entries: {r.get('count')}")
    for e in r.get("entries", [])[:4]:
        print(f"    {e['cveID']}  {e['dateAdded']}  {e['product']}")

    print("\n=== Exploit-DB stream ===")
    r = exploitdb_latest(5)
    for it in r.get("items", [])[:5]:
        print(f"    {it['title'][:70]}")

    print("\n=== hash lookup (expects a clear key requirement) ===")
    print("  ", hash_lookup("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))
