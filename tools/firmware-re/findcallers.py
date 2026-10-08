#!/usr/bin/env python3
"""
Find which binaries in an extracted rootfs reference a library symbol.

Static reachability: given a target symbol exported by libpdi.so, find every
ELF in the tree that imports or references it. This is the step between
"vulnerable primitive exists" and "something reaches it".

Two passes, because linkers record references two different ways:

  1. dynamic  -- walk the .dynsym of every ELF and match the symbol name.
                 Catches binaries linked against the library.
  2. textual  -- grep the raw bytes for the symbol string. Catches binaries
                 that dlopen() and dlsym() it, which pass 1 cannot see,
                 plus anything with the name embedded in a string table.

Pass 2 over-matches, so results are reported as "candidate" and the caller
still has to confirm the reference is a real call.

    python3 findcallers.py <rootfs-dir> <symbol> [symbol ...]
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

MAGIC = b"\x7fELF"


def is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except OSError:
        return False


def walk(root: str):
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.isfile(p) and not os.path.islink(p):
                yield p


def dynamic_refs(path: str, symbols: set[str]) -> list[str]:
    """Symbols this ELF imports via .dynsym / undefined-symbol table."""
    try:
        out = subprocess.run(
            ["objdump", "-T", path],
            capture_output=True, text=True, errors="replace",
            timeout=60,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []
    if not out:
        return []
    return [ln.strip() for ln in out.splitlines() if any(s in ln for s in symbols)]


def textual_refs(path: str, symbols: set[str]) -> list[str]:
    """Symbol names present as raw bytes (catches dlopen/dlsym)."""
    try:
        size = os.path.getsize(path)
        if size > 200 * 1024 * 1024:
            return []
        with open(path, "rb") as f:
            blob = f.read()
    except OSError:
        return []
    return [s for s in symbols if s.encode() in blob]


def main() -> int:
    root = sys.argv[1]
    symbols = set(sys.argv[2:])
    if not symbols:
        print("usage: findcallers.py <rootfs> <symbol> [symbol...]")
        return 2

    print(f"rootfs   : {root}")
    print(f"symbols  : {', '.join(sorted(symbols))}\n")

    elves = [p for p in walk(root) if is_elf(p)]
    print(f"scanning {len(elves)} ELF files\n")

    dyn_hits, txt_hits = [], []
    for p in elves:
        d = dynamic_refs(p, symbols)
        if d:
            dyn_hits.append((p, d))
            continue          # a dynamic hit already proves the reference
        t = textual_refs(p, symbols)
        if t:
            txt_hits.append((p, t))

    print("=" * 70)
    print("DYNAMIC IMPORTS (strong evidence of a link)")
    print("=" * 70)
    if not dyn_hits:
        print("  none")
    for p, lines in dyn_hits:
        rel = os.path.relpath(p, root)
        for ln in lines:
            print(f"  {rel}")
            print(f"      {ln[:110]}")

    print()
    print("=" * 70)
    print("STRING-ONLY (candidate: dlopen/dlsym, or a table entry)")
    print("=" * 70)
    if not txt_hits:
        print("  none")
    for p, syms in txt_hits:
        rel = os.path.relpath(p, root)
        print(f"  {rel}  [{', '.join(syms)}]")

    print()
    print(f"summary: {len(dyn_hits)} dynamic, {len(txt_hits)} string-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())