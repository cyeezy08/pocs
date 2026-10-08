#!/usr/bin/env python3
"""
Query the Dahua public firmware download API and locate a specific platform.

The endpoint takes no authentication and the vendor publishes it openly. This
fetches a page of results and filters by platform name (Hugo, Vodka, and so
on) so the same model family can be compared across builds.

    python3 dahua_fetch.py --platform Hugo --list
    python3 dahua_fetch.py --platform Hugo --download
"""
from __future__ import annotations

import argparse
import json
import pathlib
import urllib.error
import urllib.request

API = "https://www.dahuasecurity.com/api/en/downloadCenter/firmware/list"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
OUT = pathlib.Path("/root/fw")
TIMEOUT = 45


def fetch_page(page: int, size: int = 50) -> dict:
    url = f"{API}?page={page}&size={size}"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code} on page {page}")
        return {}
    except Exception as e:
        print(f"  error: {type(e).__name__} {e}")
        return {}


def collect(platform: str, max_pages: int = 30) -> list[dict]:
    """Walk pages until we have results or run out of patience."""
    hits, seen = [], set()
    for page in range(1, max_pages + 1):
        d = fetch_page(page)
        data = d.get("data") or {}
        items = data.get("list") or []
        if not items:
            break
        for it in items:
            name = it.get("firmware_name", "")
            fid = it.get("firmware_id", "")
            if fid in seen:
                continue
            if platform.lower() in name.lower():
                seen.add(fid)
                hits.append(it)
        total = data.get("total", 0)
        print(f"  page {page:2}: {len(items):3} items, {len(hits)} matching {platform}")
        if page * 50 >= total:
            break
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", required=True, help="e.g. Hugo")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--match", default="", help="extra substring filter, e.g. HX1XXX")
    args = ap.parse_args()

    print(f"searching Dahua catalogue for platform={args.platform}\n")
    hits = collect(args.platform)
    if args.match:
        hits = [h for h in hits if args.match.lower() in h.get("firmware_name", "").lower()]

    print(f"\n{len(hits)} match(es)\n")
    for h in hits:
        name = h.get("firmware_name", "?")
        size = h.get("firmware_file_size", "?")
        md5 = h.get("firmware_md5", "?")
        print(f"  id={h.get('firmware_id')}  {size}B")
        print(f"    name : {name}")
        print(f"    md5  : {md5}")
        print(f"    url  : {h.get('firmware_url', '')[:100]}")

    if not args.download:
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for h in hits:
        url = h.get("firmware_url", "")
        if not url:
            continue
        dest = OUT / url.rsplit("/", 1)[-1]
        if dest.exists():
            print(f"  have {dest.name}")
            continue
        print(f"  downloading {dest.name} ...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=300) as r, open(dest, "wb") as f:
                while chunk := r.read(1 << 20):
                    f.write(chunk)
            print(f"    {dest.stat().st_size}B")
        except Exception as e:
            print(f"    failed: {type(e).__name__} {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())