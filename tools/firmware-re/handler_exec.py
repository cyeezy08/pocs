#!/usr/bin/env python3
"""
Correlate sonia's HTTP handler strings with its exec call sites.

Previous attempt bucketed by 8MB region and produced 16 sites in 3 regions,
which proves nothing, and paired every call site with an /api/ string
350 MB away. Both are discarded. The control test caught both.

Correct approach: handler strings live in .rodata. Code references them
through a literal pool, so the reference is an ldr with a pc-relative
offset. Walk .text for ldr instructions, resolve each literal-pool load,
and record which string address each code address loads. Then check
whether an exec call site is inside the same function as a handler load.

"Function" is approximated by proximity: a handler's string load and a
system() call within a few KB of each other are plausibly the same
handler. That is a heuristic and is labelled as one.

    python3 handler_exec.py [--near N]
"""
from __future__ import annotations

import re
import struct
import subprocess
import sys

ELF = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"

EXEC_SYMS = {"system", "popen", "execl", "execvp", "PDI_systemCmd"}
# The real on-wire path is "/cgi-bin/api/<Module>/<method>", not "/api/...".
# Matching only "/api/" at the start finds nothing, which looks identical to
# "the strings are not present".
HANDLER_RX = re.compile(r"^(?:/cgi-bin)?/api/[A-Za-z0-9_]+/[A-Za-z0-9_]+$")

# An ldr pc-relative literal load in Thumb-16 is 0100 1xxx = 0x48xx.
# ldr.w with literal is 1111 1000 0101 xxxx = 0xf85x.. plus a second halfword.
LDR16 = re.compile(r"^[0-9a-f]{4}\s+ldr\s+r\d+, \[pc")
CALL_RX = re.compile(r"^\s*([0-9a-f]+):")
PLT_RX = re.compile(r"<([A-Za-z_][A-Za-z0-9_]*)@plt")


def sections() -> dict[str, tuple[int, int, int]]:
    out = {}
    for line in subprocess.run(
        ["readelf", "-S", "--wide", ELF], capture_output=True, text=True, errors="replace"
    ).stdout.splitlines():
        p = line.split()
        if len(p) < 6 or not p[0].startswith("["):
            continue
        hexes = []
        for tok in p[3:]:
            try:
                hexes.append(int(tok, 16))
            except ValueError:
                pass
        if len(hexes) >= 3:
            out[p[1]] = (hexes[0], hexes[1], hexes[2])
    return out


def main() -> int:
    near = 4096
    if "--near" in sys.argv:
        near = int(sys.argv[sys.argv.index("--near") + 1])

    secs = sections()
    taddr, toff, tsize = secs.get(".text", (0, 0, 0))
    raddr, roff, rsize = secs.get(".rodata", secs.get(".data", (0, 0, 0)))
    print(f".text  0x{taddr:x} size 0x{tsize:x}")
    print(f"rodata 0x{raddr:x} size 0x{rsize:x}")

    # handler string addresses
    strings_out = subprocess.run(
        ["arm-linux-gnueabi-strings", "-t", "x", ELF],
        capture_output=True, text=True, errors="replace",
    ).stdout
    handlers: dict[int, str] = {}
    for line in strings_out.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        if HANDLER_RX.match(parts[1].strip()):
            handlers[int(parts[0], 16)] = parts[1].strip()
    print(f"handler strings: {len(handlers)}")
    for a, s in sorted(handlers.items()):
        print(f"  0x{a:x}  {s}")

    # exec call sites
    execs: list[tuple[int, str]] = []
    with open(ASM, errors="replace") as f:
        for line in f:
            m = CALL_RX.match(line)
            p = PLT_RX.search(line)
            if m and p and p.group(1) in EXEC_SYMS:
                execs.append((int(m.group(1), 16), p.group(1)))
    print(f"\nexec call sites: {len(execs)}")

    # handler string loads: any ldr literal whose resolved address is a handler
    loads: list[tuple[int, str]] = []
    with open(ASM, errors="replace") as f:
        for line in f:
            m = re.match(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+ldr\s+r\d+, \[pc(?:,\s*#(-?\d+))?\]", line)
            if not m:
                continue
            pc = int(m.group(1), 16)
            off = int(m.group(2)) if m.group(2) else 0
            # align pc to 4, add 4 + offset
            lit = ((pc + 4) & ~3) + off
            if lit in handlers:
                loads.append((pc, handlers[lit]))
    print(f"handler string references in code: {len(loads)}")
    for a, s in loads:
        print(f"  0x{a:x} -> {s}")

    print(f"\n=== exec sites within {near} bytes of a handler string load ===")
    found = 0
    for ea, es in execs:
        for la, ls in loads:
            if abs(ea - la) <= near:
                print(f"  0x{ea:x} {es:14} <-- {abs(ea - la)} bytes from load of {ls}")
                found += 1
    if not found:
        print("  none in that window")
        print("\n  Widen with --near, but note: proximity is a heuristic.")
        print("  A control is required. Test it by asking whether malloc")
        print("  loads also land near exec sites -- if everything does,")
        print("  proximity carries no signal and this table should be ignored.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())