"""leviathan-core CLI.

    leviathan sync    --cache cache/
    leviathan score   --inventory inv.yaml --cache cache/ --out out/
    leviathan inventory-from-httpx --file hosts.txt --domain example.com --out inv.yaml

Passive only. Authorization-gated. Explainable.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from . import __version__, config
from .assets import InventoryError, inventory_from_httpx, load_inventory
from .feeds import epss, kev
from .match import match_all
from .report import write_reports
from .score import score_matches


def cmd_sync(args: argparse.Namespace) -> int:
    cache = Path(args.cache)
    k = kev.sync(cache)
    e = epss.sync(cache)
    print(f"KEV catalog: {len(k)} CVEs (released {kev.catalog_date(cache)})")
    print(f"EPSS scores: {len(e)} CVEs (model {epss.model_date(cache)})")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    cache = Path(args.cache)
    if not (cache / "kev.json").exists() or not (cache / "epss.csv").exists():
        print("cache incomplete - run `leviathan sync --cache cache/` first", file=sys.stderr)
        return 2
    try:
        assets = load_inventory(args.inventory)
    except InventoryError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    print(f"inventory: {len(assets)} authorized asset(s) loaded")

    k = kev.sync(cache)
    e = epss.sync(cache)
    matches = match_all(assets, k)
    print(f"matched: {len(matches)} asset/CVE pair(s) against KEV")
    if not matches:
        print("no KEV matches for this inventory - queue is empty (that is a result, not an error)")
        return 0

    findings = score_matches(matches, e, cache)
    meta = {"inventory": str(args.inventory), "kev_date": kev.catalog_date(cache),
            "epss_date": epss.model_date(cache)}
    jpath, mpath = write_reports(findings, Path(args.out), meta)
    top = findings[0]
    print(f"findings: {len(findings)} -> {jpath} + {mpath}")
    print(f"top of queue: {top.summary()}")
    return 0


def cmd_from_httpx(args: argparse.Namespace) -> int:
    text = Path(args.file).read_text() if args.file else sys.stdin.read()
    inv = inventory_from_httpx(text, args.domain)
    Path(args.out).write_text(yaml.safe_dump(inv, sort_keys=False))
    print(f"inventory skeleton for {len(inv['assets'])} host(s) -> {args.out}")
    print("add CPE/product keywords per asset, keep the attestation, then run `leviathan score`.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="leviathan", description=config.POSITIONING)
    p.add_argument("--version", action="version", version=f"{config.TOOL} {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sync", help="download KEV + EPSS into cache")
    s.add_argument("--cache", default="cache")
    s.set_defaults(func=cmd_sync)

    s = sub.add_parser("score", help="score an authorized inventory against feeds")
    s.add_argument("--inventory", required=True)
    s.add_argument("--cache", default="cache")
    s.add_argument("--out", default="out")
    s.set_defaults(func=cmd_score)

    s = sub.add_parser("inventory-from-httpx", help="build inventory skeleton from httpx output")
    s.add_argument("--file", default=None, help="httpx output file (default: stdin)")
    s.add_argument("--domain", required=True)
    s.add_argument("--out", default="inventory.yaml")
    s.set_defaults(func=cmd_from_httpx)
    return p


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
