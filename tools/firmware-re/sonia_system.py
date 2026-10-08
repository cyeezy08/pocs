#!/usr/bin/env python3
"""
Resolve sonia's 9 libc system() call sites to their command strings.

siteia is mixed ARM/Thumb PIE. The pattern objdump shows is a Thumb literal
load plus PC addition:

    1cf450:  4816       ldr  r0, [pc, #88]  @ (1cf4ac ...)
    1cf452:  4478       add  r0, pc
    1cf454:  f79b edb0  blx  16afb8 <system@plt>

The literal at 1cf4ac holds an offset, not an absolute address, and the
consumer's PC completes it. Getting this wrong yields "not printable" for
every site, which is how the first attempt failed.

Note the PIE base: this binary's file offsets and virtual addresses both run
from 0, so the resolved virtual address is directly usable as a file offset.

CONTROL: at least one site must resolve to printable ASCII. Zero means the
arithmetic is wrong and no conclusion may be drawn from the output.
"""
from __future__ import annotations

import re
import struct

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"

CALL = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+bl?x?\s+[0-9a-f]+ <system@plt>")
LDR_POOL = re.compile(r"ldr\s+r0,\s*\[pc(?:,\s*#(\d+))?\]")
ADD_R0 = re.compile(r"add\s+r0,\s*pc")


def cstr(vaddr: int, limit: int = 200) -> str:
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


def main() -> int:
    lines = open(ASM, errors="replace").read().splitlines()
    sites = [i for i, l in enumerate(lines) if CALL.match(l)]
    print(f"system() call sites: {len(sites)}\n")

    resolved, unresolved = [], []

    for i in sites:
        site = int(CALL.match(lines[i]).group(1), 16)
        # search backwards for ldr r0,[pc,...] followed by add r0,pc
        for j in range(i - 1, max(0, i - 24), -1):
            line = lines[j]
            if not LDR_POOL.search(line):
                continue
            pc_l = int(line.split(":")[0].strip(), 16)
            imm = LDR_POOL.search(line).group(1)
            pool = ((pc_l + 4) & ~3) + (int(imm) if imm else 0)

            # find the matching 'add r0, pc' to get the consuming PC
            add_pc = None
            for k in range(j + 1, i):
                if ADD_R0.search(lines[k]):
                    add_pc = int(lines[k].split(":")[0].strip(), 16) + 4
                    break
            if add_pc is None:
                unresolved.append((site, f"pool 0x{pool:x} but no 'add r0, pc'"))
                break

            try:
                with open(SONIA, "rb") as f:
                    f.seek(pool)
                    word = struct.unpack("<I", f.read(4))[0]
            except OSError:
                unresolved.append((site, f"cannot read pool 0x{pool:x}"))
                break

            va = (word + add_pc) & 0xFFFFFFFF
            s = cstr(va)
            if s:
                resolved.append((site, va, s))
            else:
                # sometimes the pool word IS the address
                s2 = cstr(word)
                if s2:
                    resolved.append((site, word, s2))
                else:
                    unresolved.append(
                        (site, f"pool=0x{pool:x} word=0x{word:x} addpc=0x{add_pc:x} "
                               f"-> 0x{va:x} not printable")
                    )
            break

    print(f"=== resolved: {len(resolved)} ===")
    for site, va, s in resolved:
        print(f"  0x{site:x}  0x{va:x}  {s!r}")

    print(f"\n=== unresolved: {len(unresolved)} ===")
    for site, why in unresolved:
        print(f"  0x{site:x}  {why}")

    print("\nCONTROL:", "PASS" if resolved else "FAIL (zero resolved)")
    if not resolved:
        print("  The Thumb literal-load arithmetic is wrong. Discard the")
        print("  unresolved list too; it is an artefact of the same bug.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())