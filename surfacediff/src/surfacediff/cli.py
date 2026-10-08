"""surfacediff CLI - snap, diff, show. PD-style UX: -json, -silent, pipelines."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, config
from .diff import diff_records
from .normalize import parse_stream
from .store import latest_pair, list_snapshots, load, snap, store_dir

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _read_input(path: str | None) -> str:
    if path in (None, "-"):
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _parse_tags(pairs: list[str] | None) -> dict:
    tags = {}
    for p in pairs or []:
        if "=" not in p:
            raise ValueError(f"--tag wants k=v, got {p!r}")
        k, v = p.split("=", 1)
        tags[k] = v
    return tags


def cmd_snap(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    assets, warnings = parse_stream(text)
    if not assets:
        if not args.silent:
            print("no assets parsed - nothing snapshotted", file=sys.stderr)
        return config.EXIT_ERROR
    tags = _parse_tags(args.tag)
    if args.source:
        tags["source"] = args.source
    path = snap(args.dir, args.label, assets, tags)
    if not args.silent:
        print(f"{GREEN}snapshotted{RESET} {len(assets)} asset(s) -> {path}")
    for w in warnings[:5]:
        print(f"{DIM}warn: {w}{RESET}", file=sys.stderr)
    return config.EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        old, new = latest_pair(args.dir, args.label, args.from_ref)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return config.EXIT_ERROR
    result = diff_records(old["records"], new["records"])
    result["label"] = args.label
    result["from"] = old["file"]
    result["to"] = new["file"]

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _render(result, args.no_color or not sys.stdout.isatty())

    if not old["records"] and new["records"]:
        if not args.json and not args.silent:
            print(f"{DIM}note: first snapshot for this label - baseline recorded; "
                  f"changes show up on the next diff{RESET}", file=sys.stderr)
        return config.EXIT_OK
    return config.EXIT_CHANGES if result["has_changes"] else config.EXIT_OK


def _render(result: dict, plain: bool) -> None:
    c = (lambda s, code: s) if plain else (lambda s, code: code + s + RESET)
    counts = result["counts"]
    added_s = c("+" + str(counts["added"]), GREEN)
    removed_s = c("-" + str(counts["removed"]), RED)
    changed_s = c("~" + str(counts["changed"]), YELLOW)
    print(f"label {result['label']}: {added_s} {removed_s} {changed_s}")
    print(c(result["from"] + " -> " + result["to"], DIM))
    for r in result["added"]:
        print("  " + c("+", GREEN) + " " + r["key"])
    for r in result["removed"]:
        print("  " + c("-", RED) + " " + r["key"])
    for r in result["changed"]:
        print("  " + c("~", YELLOW) + " " + r["key"])
        d = r["delta"]
        for k in sorted(set(d["added"]) | set(d["changed"])):
            if k in d["changed"]:
                print(f"      {k}: {d['changed'][k]['from']} -> {d['changed'][k]['to']}")
            else:
                print(f"      {k}: (none) -> {d['added'][k]}")
        for k in sorted(d["removed"]):
            print(f"      {k}: removed")


def cmd_show(args: argparse.Namespace) -> int:
    try:
        snaps = list_snapshots(args.dir, args.label)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return config.EXIT_ERROR
    if not snaps:
        print(f"no snapshots for label {args.label!r}", file=sys.stderr)
        return config.EXIT_ERROR
    for name in snaps:
        data = load(args.dir, args.label, name)
        n = len(data["records"])
        ts = data["meta"].get("timestamp", "?")
        tags = data["meta"].get("tags", {})
        tag_s = " ".join(f"{k}={v}" for k, v in tags.items())
        print(f"{name}  {ts}  {n} asset(s)  {tag_s}")
    return config.EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=config.TOOL,
        description=f"{config.TAGLINE}. Feeds on ProjectDiscovery output.")
    p.add_argument("--version", action="version", version=f"{config.TOOL} {__version__}")
    p.add_argument("--dir", default=None, help=f"store dir (default ./{config.DEFAULT_DIR}, env {config.ENV_DIR})")
    p.add_argument("--silent", action="store_true", help="suppress non-essential output")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snap", help="snapshot tool output from stdin or -i")
    s.add_argument("-l", "--label", required=True, help="surface label (e.g. subs, web, ports)")
    s.add_argument("-i", "--input", default=None, help="input file (default: stdin)")
    s.add_argument("--tag", action="append", metavar="K=V", help="metadata tag (repeatable)")
    s.add_argument("--source", default=None, help="source hint, e.g. httpx/subfinder/naabu")
    s.set_defaults(func=cmd_snap)

    s = sub.add_parser("diff", help="diff last two snapshots (exit 1 = changes)")
    s.add_argument("-l", "--label", required=True)
    s.add_argument("--from", dest="from_ref", default=None, help="compare from this snapshot instead")
    s.add_argument("--json", action="store_true", help="machine output")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("show", help="list snapshots for a label")
    s.add_argument("-l", "--label", required=True)
    s.set_defaults(func=cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return config.EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
