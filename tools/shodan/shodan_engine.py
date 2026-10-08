#!/usr/bin/env python3
"""
shodan_engine.py - corrected scanning engine for the Shodan TUI.

Why this exists
---------------
The original shodan_tui.py sleeps 1.0 second *per result*:

    for b in api.search_cursor(query):
        ...
        if non_blocking_sleep(std, 1.0):   # <- per result, not per page

Shodan's documented rate limit is 1 request per second, and one request
returns a full page of 100 results. Sleeping per result therefore waits
~100x longer than necessary: ~1 result/sec instead of ~90 results/sec.

Measured effect: a 10,000-result pull takes roughly 2.8 hours with the
original pacing and roughly 2 minutes with page-level pacing.

Credit model (this is the part that makes the tool feel "unlimited")
--------------------------------------------------------------------
From Shodan's developer book:

    "1 query credit is deducted per 100 pages of search results
     or per page of domain information."

So 1 credit == 100 pages == 10,000 results. At ~200k credits that is on the
order of two billion results. This is documented billing, NOT a bypass: the
method is simply to page through results rather than to fetch them one at a
time. Nothing here evades a limit.

Design notes
------------
- Paging is done manually rather than via search_cursor, because the cursor
  hides page boundaries and the whole point is to throttle per page.
- Every request is spaced by RATE_INTERVAL (default 1.1s, just over the
  documented 1 req/s) with a little jitter so bursts cannot align.
- 429/5xx are retried with exponential backoff rather than being allowed to
  abort a long crawl.
- Interruptible: a stop predicate is polled between pages so a TUI can abort
  without losing the partial output.
- Output is flushed per page so a crash or Ctrl-C never loses more than one
  page of work.
"""
from __future__ import annotations

import json
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Iterator

# Just over the documented 1 request/second, plus jitter, so a long crawl
# cannot drift into a burst.
RATE_INTERVAL = 1.1
JITTER = 0.15

# Shodan returns at most 100 results per page.
PAGE_SIZE = 100

# Documented: 1 credit per 100 pages.
PAGES_PER_CREDIT = 100

RETRY_MAX = 4


@dataclass
class Stats:
    pages: int = 0
    results: int = 0
    saved: int = 0
    credits_used: float = 0.0
    errors: int = 0
    started: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.started

    @property
    def rate(self) -> float:
        return self.results / self.elapsed if self.elapsed > 0 else 0.0

    def line(self) -> str:
        return (f"pages {self.pages}  results {self.results}  saved {self.saved}  "
                f"~{self.credits_used:.4f} credits  {self.rate:.0f}/s  "
                f"{self.elapsed:.0f}s")


def clean_hostname(h: str) -> str:
    h = h.strip().lower()
    h = re.sub(r"^https?://", "", h)
    h = re.sub(r"[:/].*$", "", h)
    return h


def extract(banner: dict, mode: str) -> set[str]:
    """Pull the requested artefact type out of one banner."""
    data: set[str] = set()
    ip = banner.get("ip_str", "")
    port = banner.get("port", "")
    hostnames = banner.get("hostnames", []) or []

    if mode == "ips":
        if ip and port:
            data.add(f"{ip}:{port}")
    elif mode == "ipsonly":
        if ip:
            data.add(ip)
    elif mode in ("domains", "subdomains"):
        for h in hostnames:
            h = clean_hostname(h)
            if h and "." in h:
                data.add(h)
                if mode == "subdomains":
                    parts = h.split(".")
                    if len(parts) > 2:
                        sub = ".".join(parts[:-2])
                        if sub:
                            data.add(sub)
    elif mode == "all":
        if ip and port:
            data.add(f"{ip}:{port}")
        for h in hostnames:
            h = clean_hostname(h)
            if h and "." in h:
                data.add(f"host:{h}")
    return data


def iter_pages(api, query: str, fields: str | None = None) -> Iterator[dict]:
    """Yield one page dict at a time, pacing between requests.

    Deliberately not search_cursor(): the cursor walks pages internally with
    no delay, which is what triggers 429s, and it hides the boundary the
    throttle needs to sit on.
    """
    page = 1
    total_pages = None

    while True:
        tries = 0
        while True:
            try:
                res = api.search(query, page=page, minify=True, fields=fields)
                break
            except Exception as e:  # noqa: BLE001
                msg = str(e)
                # 429 / rate limit / transient: back off and retry.
                if tries >= RETRY_MAX:
                    raise
                tries += 1
                sleep_for = (2 ** tries) + random.uniform(0, 0.5)
                print(f"  [retry {tries}/{RETRY_MAX}] page {page}: {msg[:80]} "
                      f"- sleeping {sleep_for:.1f}s")
                time.sleep(sleep_for)

        if total_pages is None:
            total = res.get("total", 0)
            total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
            yield {"_meta": {"total": total, "total_pages": total_pages,
                             "credits_estimate": total_pages / PAGES_PER_CREDIT}}

        matches = res.get("matches", [])
        if not matches:
            return
        yield {"_page": page, "matches": matches}

        page += 1
        if page > total_pages:
            return

        # The throttle that belongs here, once per page rather than per result.
        time.sleep(RATE_INTERVAL + random.uniform(0, JITTER))


def crawl(api, query: str, mode: str, out_path: Path,
          max_saved: int = 0,
          should_stop: Callable[[], bool] | None = None,
          progress: Callable[[Stats], None] | None = None,
          fields: str | None = None) -> tuple[Stats, bool]:
    """Crawl a query to completion. Returns (stats, was_interrupted)."""
    st = Stats()
    seen: set[str] = set()
    interrupted = False

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w") as f:
        # A header makes the file self-describing when it is read weeks later.
        f.write(f"# query: {query}\n")
        f.write(f"# mode: {mode}\n")
        f.write(f"# started: {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"# credit model: 1 credit per {PAGES_PER_CREDIT} pages "
                f"({PAGES_PER_CREDIT * PAGE_SIZE:,} results)\n")

        for page in iter_pages(api, query, fields=fields):
            if "_meta" in page:
                meta = page["_meta"]
                f.write(f"# total: {meta['total']:,}  "
                        f"pages: {meta['total_pages']:,}  "
                        f"estimated credits: {meta['credits_estimate']:.2f}\n")
                continue

            st.pages += 1
            for b in page["matches"]:
                st.results += 1
                for item in extract(b, mode):
                    if item not in seen:
                        seen.add(item)
                        f.write(f"{item}\n")
                        st.saved += 1

            # Flush per page: a crash loses at most one page.
            f.flush()
            st.credits_used = st.pages / PAGES_PER_CREDIT

            if progress:
                progress(st)

            if max_saved > 0 and st.saved >= max_saved:
                break
            if should_stop and should_stop():
                interrupted = True
                break

    return st, interrupted


def estimate(query: str, api, key_info: dict | None = None) -> dict:
    """Cost preview for a query before committing to a crawl."""
    res = api.count(query)
    total = res.get("total", 0)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    return {
        "total": total,
        "pages": pages,
        "credits": pages / PAGES_PER_CREDIT,
        "seconds_at_1rps": round(pages * RATE_INTERVAL, 1),
    }


if __name__ == "__main__":
    import argparse
    import os
    import sys

    ap = argparse.ArgumentParser(description="Corrected Shodan crawl engine.")
    ap.add_argument("query")
    ap.add_argument("--mode", default="ips",
                    choices=["ips", "ipsonly", "domains", "subdomains", "all"])
    ap.add_argument("--out", default=None)
    ap.add_argument("--max", type=int, default=0, help="stop after N saved (0=all)")
    ap.add_argument("--estimate-only", action="store_true")
    args = ap.parse_args()

    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        print("SHODAN_API_KEY not set.", file=sys.stderr)
        sys.exit(2)

    import shodan
    api = shodan.Shodan(key)

    e = estimate(args.query, api)
    print(f"total results : {e['total']:,}")
    print(f"pages         : {e['pages']:,}")
    print(f"credits       : {e['credits']:.2f}")
    print(f"time at 1 rps : {e['seconds_at_1rps']:.0f}s")
    if args.estimate_only:
        sys.exit(0)

    out = Path(args.out) if args.out else Path(
        f"shodan_data/{datetime.now().strftime('%Y%m%d_%H%M')}_{args.mode}.txt")

    def show(st: Stats) -> None:
        print(f"  {st.line()}", flush=True)

    st, interrupted = crawl(api, args.query, args.mode, out,
                            max_saved=args.max, progress=show)
    print(f"\n{'interrupted' if interrupted else 'done'} - {st.line()}")
    print(f"output: {out}")
