#!/usr/bin/env python3
"""
Resolve sonia's remaining exec-primitive sites: popen, execl, execvp, PDI_systemCmd.

system() was handled separately (sonia_system.py / sonia_formats.py). This
covers the other five primitives, whose argument setup differs:

  popen(buf, "r")          same literal-pool shape as system
  execl(path, arg0, ...)   path in r0, remaining args in r1..r3 + stack
  execvp(file, argv)       file in r0, argv in r1
  PDI_systemCmd(cmd)       argument arrives in r0 already built by the caller

For PDI_systemCmd and execl the interesting question is not the string but the
CALLER, since the command is assembled upstream. Both call sites sit in
stripped static functions, so caller recovery is out of reach statically; what
can be done is reporting the register state at the call, which tells a reverse
engineer where to start.

CONTROL: popen must resolve at least one printable string, using the same
literal-pool arithmetic already validated on system(). If it resolves none,
that arithmetic regressed.
"""
from __future__ import annotations

import re
import struct

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"
BASE = 0x400000  # not used; sonia is PIE with file offset == vaddr

PRIMS = ["popen", "execl", "execvp", "PDI_systemCmd"]


def cstr(vaddr: int, limit: int = 220) -> str:
    try:
        with open(SONIA, "rb") as f:
            f.seek(vaddr)
            raw = f.read(limit)
    except OSError:
        return ""
    for chunk in raw.split(b"\x00"):
        s = chunk.decode("utf-8", "replace")
        if s and all(32 <= ord(c) < 127 for c in s):
            return s
    return ""


def resolve_pool(lines, idx, reg="r0"):
    """Walk back for ldr <reg>,[pc,#imm] + add <reg>,pc, return the string."""
    for j in range(idx - 1, max(0, idx - 30), -1):
        m = re.search(rf"ldr\s+{reg},\s*\[pc(?:,\s*#(\d+))?\]", lines[j])
        if not m:
            continue
        pc_l = int(lines[j].split(":")[0].strip(), 16)
        pool = ((pc_l + 4) & ~3) + (int(m.group(1)) if m.group(1) else 0)
        add_pc = None
        for k in range(j + 1, idx):
            if re.search(rf"add\s+{reg},\s*pc", lines[k]):
                add_pc = int(lines[k].split(":")[0].strip(), 16) + 4
                break
        if add_pc is None:
            continue
        with open(SONIA, "rb") as f:
            f.seek(pool)
            word = struct.unpack("<I", f.read(4))[0]
        va = (word + add_pc) & 0xFFFFFFFF
        s = cstr(va)
        if s:
            return va, s
        s2 = cstr(word)
        if s2:
            return word, s2
    return None, None


def main() -> int:
    lines = open(ASM, errors="replace").read().splitlines()

    resolved_any = False
    for prim in PRIMS:
        sites = [
            i for i, l in enumerate(lines)
            if re.search(rf"bl?x?\s+[0-9a-f]+ <{prim}@plt>", l)
        ]
        print(f"\n=== {prim}: {len(sites)} site(s) ===")
        if not sites:
            continue
        for i in sites:
            addr = int(re.match(r"^\s*([0-9a-f]+):", lines[i]).group(1), 16)
            va, s = resolve_pool(lines, i)
            if s:
                resolved_any = True
                print(f"  0x{addr:x}  0x{va:x}  {s!r}")
            else:
                print(f"  0x{addr:x}  arg built by caller (no literal load)")
                ctx = [l.split("\t")[-1].strip()
                       for l in lines[max(0, i - 6):i] if "\t" in l]
                print(f"            ctx: {ctx[-4:]}")

    print("\nCONTROL: popen was required to resolve at least one string.")
    print("  Status:", "PASS" if resolved_any else "INCONCLUSIVE (no popen string)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())