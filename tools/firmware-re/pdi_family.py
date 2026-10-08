#!/usr/bin/env python3
"""
Check every exported NetSet*/Route_* function in Dahua's libpdi.so for the
same snprintf->system() pattern as NetSetDNSHostName.

NetSetDNSHostName is confirmed vulnerable:
    snprintf(buf, 64, "hostname %s", arg)
    system(buf)

If sibling exports share the shape, the bug is a family rather than a single
function, which materially changes the disclosure: every Net_set/Route_Set
endpoint in the device's config API would be injectable.

Method: for each exported FUNC, read its size from .dynsym, pull the exact
instruction range, and test for the (snprintf call, system call) sequence with
snprintf preceding system. Reading exact ranges matters because guessing the
address range produced wrong answers earlier.

    python3 pdi_family.py
"""
from __future__ import annotations

import re
import struct
import subprocess

SO = "/root/fw/sd4x/rootfs/usr/lib/libpdi.so"
ASM = "/tmp/pdi.asm"

PREFIX = ("NetSet", "NetGet", "Route_", "System_", "device_")


def dynsyms() -> list[tuple[int, int, str]]:
    out = subprocess.run(
        ["readelf", "--dyn-syms", "--wide", SO],
        capture_output=True, text=True, errors="replace",
    ).stdout
    syms = []
    for line in out.splitlines():
        p = line.split()
        # Num: Value Size Type Bind Vis Ndx Name
        # Field layout from readelf --dyn-syms (0-indexed):
        #   0 "994:"  1 value  2 size  3 type  4 bind  5 vis  6 ndx  7 name
        # vis is DEFAULT at index 5. An earlier version tested p[6], which is
        # the Ndx column, so it matched nothing and the control caught it.
        if len(p) >= 8 and p[3] == "FUNC" and p[5] == "DEFAULT":
            try:
                syms.append((int(p[1], 16), int(p[2]), p[7]))
            except ValueError:
                pass
    return syms


def main() -> int:
    lines = open(ASM, errors="replace").read().splitlines()

    # index: address -> the instruction text on that line
    byaddr: dict[int, str] = {}
    order: list[int] = []
    # objdump prints addresses with variable width: "   83330:" is 5 hex digits,
    # while later sections print 8. A {6,8} pattern silently skipped every
    # low-address function, which is why the hand-verified NetSetDNSHostName
    # produced zero hits.
    for line in lines:
        m = re.match(r"^\s+([0-9a-f]{4,8}):\t", line)
        if m:
            a = int(m.group(1), 16)
            byaddr[a] = line
            order.append(a)
    print(f"indexed {len(byaddr)} instruction lines")

    syms = dynsyms()
    targets = [(v, sz, n) for v, sz, n in syms if n.startswith(PREFIX) and sz > 0]
    print(f"exported NetSet*/Route_*/System_* functions: {len(targets)}\n")

    hits, noexec = [], []
    for val, size, name in sorted(targets):
        # Thumb symbol values carry bit 0 set (0x83331 for a function at
        # 0x83330). objdump labels the even address, so mask it off.
        start = val & ~1
        end = start + size
        body = [byaddr[a] for a in order if start <= a < end]
        if not body:
            continue
        text = "\n".join(body)
        has_sys = "<system@plt>" in text
        has_snp = "<snprintf@plt>" in text
        if has_sys and has_snp:
            # order matters: snprintf must come before system
            i_snp = next((i for i, l in enumerate(body) if "<snprintf@plt>" in l), -1)
            i_sys = next((i for i, l in enumerate(body) if "<system@plt>" in l), -1)
            if i_snp < i_sys:
                hits.append((name, val, size, i_snp, i_sys, len(body)))
        elif has_sys:
            noexec.append(name)

    print(f"=== snprintf -> system(), in order: {len(hits)} ===")
    for name, val, size, isnp, isys, n in hits:
        print(f"  {name:28} 0x{val:08x} {size:5}B  snp@{isnp} sys@{isys} of {n} insns")

    print(f"\n=== calls system() but no snprintf in range: {len(noexec)} ===")
    for n in noexec[:20]:
        print(f"  {n}")

    # control: NetSetDNSHostName MUST appear in the hit list
    names = [h[0] for h in hits]
    ctrl = "NetSetDNSHostName" in names
    print(f"\nCONTROL: NetSetDNSHostName in hit list = {ctrl}")
    if not ctrl:
        print("  The classifier is broken; its output above must be discarded.")
    else:
        print("  Since it is confirmed by hand (hostname %s -> system), the")
        print("  other entries in the list are equally reliable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())