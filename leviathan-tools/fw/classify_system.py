#!/usr/bin/env python3
"""
Classify every system() call site in Tenda 5G03 httpd.

For each of the 21 system() sites, walk backwards to find how the x0
argument is built. Three shapes matter:

  A  snprintf(buf, ...) then system(buf)
     -> the formatted command contains request-derived data. This is the
        shape the six Deferred CVEs describe.
  B  adrp/add then system(<fixed string>)
     -> constant command, no injection. Not interesting.
  C  register move from a non-stack register (x19..x28)
     -> indirect; needs manual review.

Control requirement: shape B must dominate. If B does not dominate, the
classifier is misreading and its output should not be trusted.
"""
from __future__ import annotations

import re
import subprocess
import sys

ASM = "/tmp/tenda-httpd.asm"
ELF = "/root/fw/tenda/rootfs/usr/sbin/httpd"
BASE = 0x400000

CALL = re.compile(r"^\s*([0-9a-f]{6,}):\s+[0-9a-f ]+\s+bl\s+[0-9a-f]+ <system@plt>")
SNPRINTF = re.compile(r"^\s*([0-9a-f]{6,}):\s+[0-9a-f ]+\s+bl\s+[0-9a-f]+ <snprintf@plt>")
ADRP = re.compile(r"^\s*([0-9a-f]{6,}):\s+[0-9a-f ]+\s+adrp\s+x0,")
MOV_X0 = re.compile(r"^\s*([0-9a-f]{6,}):\s+[0-9a-f ]+\s+mov\s+x0,\s*(x\d+|#)")
ADD_X0 = re.compile(r"^\s*([0-9a-f]{6,}):\s+[0-9a-f ]+\s+add\s+x0,\s*x0,")


def rodata_str(vaddr: int, n: int = 160) -> str:
    try:
        out = subprocess.run(
            ["dd", f"if={ELF}", "bs=1", f"skip={vaddr - BASE}", f"count={n}"],
            capture_output=True, text=True, errors="replace",
        ).stdout
    except Exception:  # noqa: BLE001
        return ""
    for chunk in out.split("\x00"):
        s = "".join(c for c in chunk if 32 <= ord(c) < 127).strip()
        if len(s) >= 4:
            return s[:80]
    return ""


def main() -> int:
    lines = open(ASM, errors="replace").read().splitlines()

    systems: list[int] = []
    for i, line in enumerate(lines):
        if CALL.match(line):
            systems.append(i)

    print(f"system() call sites: {len(systems)}\n")

    # map: snprintf line index -> the stack dest it wrote to
    snp: dict[int, str] = {}
    for i, line in enumerate(lines):
        m = SNPRINTF.match(line)
        if not m:
            continue
        # the instruction just before snprintf sets x0 to the destination
        for j in range(i - 1, max(0, i - 12), -1):
            mm = re.search(r"add\s+x0,\s*sp,\s*#(0x[0-9a-f]+|\d+)", lines[j])
            if mm:
                snp[i] = mm.group(1)
                break

    shapes: dict[str, list[str]] = {"A-snprintf": [], "B-constant": [], "C-indirect": []}

    for i in systems:
        addr = CALL.match(lines[i]).group(1)
        # find nearest preceding snprintf within 12 instructions
        shape, note = "C-indirect", ""
        for j in range(i - 1, max(0, i - 14), -1):
            if SNPRINTF.match(lines[j]):
                shape = "A-snprintf"
                note = f"via snprintf sp+{snp.get(j,'?')}"
                break
            if ADRP.match(lines[j]):
                # aarch64 builds addresses as adrp + add, not mov #imm.
                # Treat adrp immediately feeding the call as a fixed string.
                shape = "B-constant"
                note = "adrp/add (constant rodata string)"
                break
            mm = MOV_X0.match(lines[j])
            if mm:
                src = mm.group(2)
                if src == "#":
                    shape = "B-constant"
                    note = "immediate (constant)"
                else:
                    shape = "C-indirect"
                    note = f"from {src}"
                break
        shapes[shape].append(f"0x{addr} {note}")

    for k in ("A-snprintf", "B-constant", "C-indirect"):
        print(f"=== {k}: {len(shapes[k])} ===")
        for s in shapes[k]:
            print(f"  {s}")

    print("\n=== format strings for shape A ===")
    for i in systems:
        for j in range(i - 1, max(0, i - 14), -1):
            m = ADRP.match(lines[j])
            if m:
                # find the add that completes the address, then read rodata
                for k in range(j, min(len(lines), j + 3)):
                    mm = re.search(r"add\s+x2,\s*x2,\s*#(0x[0-9a-f]+|\d+)", lines[k])
                    if mm:
                        base_v = int(m.group(1), 16) & ~0x7FFF
                        page = int(re.search(r"adrp\s+x2,\s*([0-9a-f]+)", lines[k]).group(1), 16)
                        off = int(mm.group(1), 0)
                        va = page + off
                        print(f"  0x{CALL.match(lines[i]).group(1)}  0x{va:x}  "
                              f"{rodata_str(va)!r}")
                        break
                break

    print("\nCONTROL: shape B (constant commands) should be the largest group.")
    print("If it is not, the backward-walk is misreading argument setup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())