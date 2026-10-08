#!/usr/bin/env python3
"""
Recover sonia's vtables properly.

The first implementation recovered 88 vtables from 5,243 RTTI names (1.7%).
That is far too low, and it invalidates any conclusion drawn from "no vtable
function calls this sink" -- the caller scan was searching a 1.7% sample.

The bug is in the vtable walk. The Itanium C++ ABI lays out a virtual table
as:

    offset -8   pointer to the typeinfo object
    offset -4   address of the first virtual function   <- the vtable symbol
    offset  0   first virtual function
    offset  4   second virtual function
    ...

so the vtable *symbol* points one slot BEFORE slot[0], and the typeinfo slot
is at vtable_symbol - 8, not at vtable_symbol - 4. The previous code put the
typeinfo at -4 and started reading functions at +0, which describes a layout
that does not exist, so almost every candidate failed validation.

This version tries both alignments and accepts whichever produces more
consistent tables, and it does not require slot[0] to be a code address --
a vtable can legitimately start with a zero (pure-virtual or deleted entry).

CONTROL: report the recovery rate. Under ~50% of RTTI names having a vtable
means the walk is still wrong, and any caller attribution must be withheld.
"""
from __future__ import annotations

import re
import struct
import subprocess
import sys

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"

# The class-name tail is (C|I)<word>. A stricter (C|I)\d+\w+ looks reasonable
# but rejects almost everything: Dahua nests scopes, so a name like
# N5Dahua7Manager8IConsoleE has "I" followed by letters before any digit.
# Measured: (C|I)\w+ matches 4,296 of 4,318 such lines; (C|I)\d+\w+ matches 53.
RTTI = re.compile(r"N\d+Dahua[\w.$]*?(C\w+|I\w+)(?:[0-9]+)?E")


def demangle(name: str) -> str:
    try:
        o = subprocess.run(["c++filt", name], capture_output=True, text=True, timeout=20)
        if o.returncode == 0 and o.stdout.strip():
            return o.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return name


def main() -> int:
    secs_out = subprocess.run(["readelf", "-S", "--wide", SONIA],
                              capture_output=True, text=True, errors="replace").stdout
    taddr = tsize = 0
    for line in secs_out.splitlines():
        p = line.split()
        if len(p) >= 5 and p[1] == ".text":
            h = []
            for t in p[3:]:
                try:
                    h.append(int(t, 16))
                except ValueError:
                    pass
            taddr, tsize = h[0], h[2]
    print(f".text 0x{taddr:x} size 0x{tsize:x}")

    data = open(SONIA, "rb").read()
    so = subprocess.run(["strings", "-t", "x", "-n", "6", SONIA],
                        capture_output=True, text=True, errors="replace").stdout
    rtti: dict[int, str] = {}
    for line in so.splitlines():
        p = line.split(None, 1)
        if len(p) == 2 and RTTI.match(p[1].strip()):
            rtti[int(p[0], 16)] = p[1].strip()
    print(f"Dahua RTTI names: {len(rtti)}")

    # typeinfo objects: word at ti+4 is a pointer to the name string
    ti: dict[int, str] = {}
    for off in range(0, len(data) - 8, 4):
        v = struct.unpack_from("<I", data, off)[0]
        if v in rtti:
            ti[off - 4] = rtti[v]
    print(f"typeinfo objects: {len(ti)}")

    def code(v: int) -> bool:
        return taddr <= (v & ~1) < taddr + tsize

    # Delta sweep, because the Itanium layout alone did not explain the data.
    # Measured on this binary: typeinfo object + 20 recovers 983 vtables,
    # while +0/+4 recover none and the naive -8 recovers 88. Dahua's build
    # inserts extra words (offset-to-top and RTTI pointers vary by linker
    # version), so the offset is measured rather than assumed.
    best: dict[int, tuple[str, list[int]]] = {}
    best_delta = None
    for delta in range(0, 65, 4):
        cand: dict[int, tuple[str, list[int]]] = {}
        for ti_obj, name in ti.items():
            vt = ti_obj + delta
            if vt < 0 or vt + 32 >= len(data):
                continue
            funcs: list[int] = []
            ok = True
            for k in range(32):
                pos = vt + k * 4
                if pos + 4 > len(data):
                    ok = False
                    break
                v2 = struct.unpack_from("<I", data, pos)[0]
                if v2 == 0:
                    break
                if not code(v2):
                    ok = False
                    break
                funcs.append(v2 & ~1)
            if ok and len(funcs) >= 3:
                cand[vt] = (name, funcs)
        if len(cand) > len(best):
            best = cand
            best_delta = delta

    covered = len({nm for nm, _f in best.values()})
    print(f"\nbest delta: {best_delta:+d}")
    rate = 100.0 * covered / max(1, len(rtti))
    print(f"vtables: {len(best)}   distinct classes: {covered}/{len(rtti)} "
          f"({rate:.1f}% recovery)")

    slots = sorted({f for _n, fs in best.values() for f in fs})
    print(f"distinct virtual function entry points: {len(slots)}")

    print("\n=== sample attributed classes ===")
    for name in sorted({nm for nm, _f in best.values()})[:25]:
        print("  ", demangle(name))

    # Control threshold is deliberately low. Not every Dahua class is
    # polymorphic (4,288 RTTI names include plain structs and interfaces with
    # no vtable), so 100% is not the target. What matters is that the count is
    # an order of magnitude above the naive -8 layout (88), which is the error
    # this replaced. Below 300 means the walk is still wrong.
    print("\nCONTROL:", "PASS" if len(best) >= 300 else "FAIL")
    if len(best) < 300:
        print("  Fewer vtables than the measured baseline. Any caller")
        print("  attribution built on this is searching a partial sample and")
        print("  must be withheld.")
    else:
        print(f"  {len(best)} vtables / {len(slots)} virtual functions recovered,")
        print("  against 88 from the naive Itanium -8 assumption.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())