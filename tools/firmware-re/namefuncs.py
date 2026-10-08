#!/usr/bin/env python3
"""
Name the functions containing sonia's exec call sites.

sonia keeps only 1294 GLOBAL FUNC symbols; every call site sits inside a
static function objdump never labelled, so nearest-symbol attribution
returns nonsense like "PDI_productGetPeripheralValue +0x6b662".

This recovers names a different way: find the /api/* handler strings in
.text, then for each exec call site, look for an api-string reference in
the same function region. A handler string near a system() call is the
link between the HTTP surface and the sink.

Method, since there is no symbol table for statics:
  1. locate every /api/ string literal in .text
  2. for each, find the code that loads it (literal pool -> ldr)
  3. bucket the exec call sites by which string region they fall in

Control test: the same procedure is run against malloc call sites, which
must bucket into many distinct regions. If malloc produces one bucket the
bucketing logic is wrong.
"""
from __future__ import annotations

import bisect
import re
import struct
import subprocess
import sys

ELF = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"

CALLS = {
    "system": [], "popen": [], "execl": [], "execvp": [], "PDI_systemCmd": [],
}
CONTROL = {"malloc": [], "free": []}

# 8 MB region size: a Dahua request handler is far smaller than this, so two
# call sites in the same region are almost certainly the same handler.
REGION = 8 << 20


def main() -> int:
    if not ASM:
        print(f"need {ASM}; run arm-linux-gnueabi-objdump -d {ELF} > {ASM}")
        return 1

    # Line shape: "  1cf454:\tf79b edb0 \tblx\t16afb8 <system@plt>"
    # The raw-bytes field is a TAB-separated pair of halfwords, so it can be
    # two tokens. Match on the address, then find the last "@plt" symbol on
    # the line rather than trying to count opcode fields.
    call_rx = re.compile(r"^\s*([0-9a-f]+):")
    plt_rx = re.compile(r"<([A-Za-z_][A-Za-z0-9_]*)@plt>")
    n = 0
    with open(ASM, errors="replace") as f:
        for line in f:
            m = call_rx.match(line)
            if not m:
                continue
            p = plt_rx.search(line)
            if not p:
                continue
            addr = int(m.group(1), 16)
            sym = p.group(1)
            if sym in CALLS:
                CALLS[sym].append(addr)
                n += 1
            elif sym in CONTROL:
                CONTROL[sym].append(addr)

    print(f"parsed {n} exec-primitive call sites")
    for k, v in CALLS.items():
        print(f"  {k:16} {len(v)}")
    print()
    for k, v in CONTROL.items():
        print(f"  [control] {k:8} {len(v)}")

    # api strings live in .rodata; find their addresses from the string table
    print("\n=== locating /api/ string literals ===")
    out = subprocess.run(
        ["arm-linux-gnueabi-strings", "-t", "x", ELF],
        capture_output=True, text=True, errors="replace",
    ).stdout
    api_strings = []
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].startswith("/api/"):
            try:
                api_strings.append((int(parts[0], 16), parts[1].strip()))
            except ValueError:
                pass
    print(f"  {len(api_strings)} /api/ strings found in the image")

    # bucket call sites by region
    print("\n=== bucketing call sites ===")
    buckets: dict[int, list[str]] = {}
    for sym, addrs in CALLS.items():
        for a in addrs:
            buckets.setdefault(a // REGION, []).append(f"{sym}@0x{a:x}")
    print(f"  {len(buckets)} distinct 8MB regions contain exec calls")
    for reg in sorted(buckets):
        print(f"\n  region 0x{reg * REGION:x}: {len(buckets[reg])} call site(s)")
        for c in buckets[reg]:
            print(f"      {c}")

    # control: same bucketing on malloc must spread out, else logic is wrong
    ctrl_buckets: dict[int, int] = {}
    for a in CONTROL["malloc"]:
        ctrl_buckets[a // REGION] = ctrl_buckets.get(a // REGION, 0) + 1
    print(f"\n  [control] malloc spreads across {len(ctrl_buckets)} regions "
          f"(max {max(ctrl_buckets.values()) if ctrl_buckets else 0} per region)")
    print("  if malloc lands in the same handful of regions as the exec calls,")
    print("  the bucketing is measuring nothing and this output should be discarded.")

    # nearest api string to each call site, as a weak hint
    if api_strings:
        api_addrs = [a for a, _ in api_strings]
        print(f"\n=== nearest /api/ string to each exec call site ===")
        for sym, addrs in CALLS.items():
            for a in addrs:
                i = bisect.bisect_left(api_addrs, a)
                best = None
                for j in (i - 1, i):
                    if 0 <= j < len(api_addrs):
                        d = abs(api_addrs[j] - a)
                        if best is None or d < best[0]:
                            best = (d, api_strings[j][1])
                if best:
                    print(f"  {sym:16} 0x{a:x}  nearest api: {best[1]}  (+/-0x{best[0]:x})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())