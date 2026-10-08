#!/usr/bin/env python3
"""
Locate PLT call sites for a given imported symbol inside one ELF.

objdump -T tells you a symbol is imported. It does not tell you where it is
called from, and that is the whole question: an imported symbol with no
reachable call site is not a path to anything.

Method: find the PLT stub address for the symbol from the relocation
table, then scan .text for BL instructions whose target is that stub.
Thumb mode is handled, because Dahua firmware is ARM and a BL is halfword-
encoded with the low bit set.

    python3 callsites.py <elf> <symbol>
"""
from __future__ import annotations

import re
import struct
import subprocess
import sys


def sh(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True, errors="replace").stdout


def plt_addr(elf: str, sym: str) -> int | None:
    """Address of the PLT stub for an imported symbol."""
    # readelf -r lists the relocation against this symbol; the addend is the stub.
    out = sh("readelf", "-r", "--wide", elf)
    for line in out.splitlines():
        if sym in line and ("JUMP_SLOT" in line or "GLOB_DAT" in line or "R_AARCH64" in line):
            m = re.search(r"([0-9a-fA-F]{8,16})\s", line)
            if m:
                return int(m.group(1), 16)
    return None


def scan_calls(elf: str, target: int, thumb: bool) -> list[int]:
    """Addresses of branch instructions resolving to `target`."""
    out = sh("objdump", "-d", "--no-show-raw-insn", elf)
    hits = []
    # objdump prints "  400abc:\tbl 400900 <run_sys@plt>"
    rx = re.compile(r"^\s*([0-9a-f]+):\s+(b|bl|b\.[a-z]+)\s+([0-9a-f]+)\s+<")
    for line in out.splitlines():
        m = rx.match(line)
        if not m:
            continue
        try:
            addr = int(m.group(1), 16)
            dest = int(m.group(3), 16)
        except ValueError:
            continue
        # Thumb BL has bit0 set on the branch target in the encoding, and the
        # printed destination already accounts for it; accept either form.
        if dest == target or dest == (target | 1):
            hits.append(addr)
    return hits


def enclosing_function(src: str, addr: int) -> str | None:
    """Nearest preceding function label in objdump output, for context."""
    rx = re.compile(r"^([0-9a-f]+)\s+<([^>]+)>:")
    best = None
    for line in src.splitlines():
        m = rx.match(line)
        if not m:
            continue
        a = int(m.group(1), 16)
        if a <= addr:
            best = (a, m.group(2))
        else:
            break
    return best[1] if best else None


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: callsites.py <elf> <symbol>")
        return 2
    elf, sym = sys.argv[1], sys.argv[2]

    if "not a dynamic" in sh("file", elf) or "ELF" not in sh("file", elf):
        print(f"not an ELF: {elf}")
        return 1

    arch = sh("readelf", "-h", elf)
    is_arm = "AArch64" in arch or "ARM" in arch
    print(f"elf    : {elf}")
    print(f"arch   : {'ARM (thumb possible)' if is_arm else 'non-ARM'}")
    print(f"symbol : {sym}\n")

    target = plt_addr(elf, sym)
    if target is None:
        print("no PLT/relocation entry found for this symbol")
        return 1
    print(f"PLT stub: 0x{target:x}\n")

    dis = sh("objdump", "-d", elf)
    sites = scan_calls(elf, target, is_arm)

    if not sites:
        print("no direct branch to the PLT stub found.")
        print("either it is called through a register/indirect path, or")
        print("there is no call site (an unused import).")
        return 1

    print(f"{len(sites)} call site(s):\n")
    for a in sites:
        fn = enclosing_function(dis, a)
        print(f"  0x{a:x}  in  {fn or '<unknown>'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())