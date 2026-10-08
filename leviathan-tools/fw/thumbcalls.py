#!/usr/bin/env python3
"""
Find Thumb-mode call sites to a PLT stub in a mixed ARM/Thumb ELF.

Context that matters, because both of these cost real time first:

  * Thumb BL is a 32-bit instruction occupying two halfwords. Scanning for
    A32 BL (opcode 0xEB) on a Thumb binary finds nothing, and "0 call sites"
    then looks like a finding instead of a broken tool. Control-test against a
    symbol that must be called (malloc) before trusting any negative result.
  * .text addresses are THUMB addresses, so bit 0 is set in the symbol table
    and in branch targets. Compare against both target and target|1.
  * The PLT stub is resolved by walking .rel.plt and indexing .dynsym by the
    Ndx column, not the Value column.

    python3 thumbcalls.py <elf> <symbol>
"""
from __future__ import annotations

import struct
import subprocess
import sys


def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, errors="replace").stdout


def sections(elf: str) -> dict[str, tuple[int, int, int]]:
    """name -> (addr, offset, size).

    Parsed positionally rather than by fixed column, because readelf puts a
    flags field in a position that varies by section type: .rel.plt shows
    "REL ... AI" while .plt shows "PROGBITS ... AX". Keying off columns 3-5
    silently fails on the sections that carry flags, which is how a
    "no PLT stub resolved" false negative appears.

    Safer: locate the hex tokens by scanning for the first three consecutive
    hex values that follow the section type, and take the last three before
    any non-numeric tail.
    """
    out: dict[str, tuple[int, int, int]] = {}
    for line in sh("readelf", "-S", "--wide", elf).splitlines():
        p = line.split()
        if len(p) < 6 or not p[0].startswith("["):
            continue
        name = p[1]
        # Section types with a flags field (REL, .rel.*) insert tokens between
        # the address and the offset, so a positional slice misses. Walk the
        # tokens and keep the ordered hex run, dropping any token that is
        # followed by a flags-like alphabetic field.
        hexes: list[int] = []
        for i, tok in enumerate(p[3:], start=3):
            try:
                val = int(tok, 16)
            except ValueError:
                continue
            nxt = p[i + 1] if i + 1 < len(p) else ""
            # a token immediately followed by flags (AX, AI, WAX, MS, ...) is
            # an entry size or flags field, not an address
            if nxt in {"AX", "AI", "WA", "WAX", "MS", "MA", "A", "W", "O", "M"}:
                continue
            hexes.append(val)
        if len(hexes) < 3:
            continue
        addr, off, size = hexes[0], hexes[1], hexes[2]
        out[name] = (addr, off, size)
    return out


def dynsym_ndx(elf: str, name: str) -> int | None:
    for line in sh("readelf", "--dyn-syms", "--wide", elf).splitlines():
        p = line.split()
        if len(p) >= 8 and p[7] == name:
            try:
                return int(p[0].rstrip(":"))
            except ValueError:
                return None
    return None


def plt_stub(secs: dict, elf: str, sym: str) -> int | None:
    idx = dynsym_ndx(elf, sym)
    if idx is None:
        return None
    _, rel_off, rel_size = secs.get(".rel.plt", (0, 0, 0))
    plt_addr = secs.get(".plt", (0, 0, 0))[0]
    if not rel_size or not plt_addr:
        return None
    with open(elf, "rb") as f:
        f.seek(rel_off)
        rel = f.read(rel_size)
    for i in range(rel_size // 8):
        _, r_info = struct.unpack("<II", rel[i * 8 : i * 8 + 8])
        if (r_info >> 8) == idx:
            return plt_addr + 20 + i * 12
    return None


def thumb_calls(text: bytes, text_addr: int, target: int) -> list[int]:
    """32-bit Thumb BL sites resolving to `target` (or target|1)."""
    t1 = target | 1
    out = []
    for i in range(0, len(text) - 3, 2):
        hi, lo = struct.unpack_from("<HH", text, i)
        if (hi & 0xF800) != 0xF000:
            continue
        if (lo & 0xD000) != 0xD000:
            continue
        s = (hi >> 10) & 1
        j1 = (lo >> 13) & 1
        j2 = (lo >> 11) & 1
        i1 = ~(j1 ^ s) & 1
        i2 = ~(j2 ^ s) & 1
        imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((hi & 0x03FF) << 12) | ((lo & 0x07FF) << 1)
        if s:
            imm -= 1 << 25
        pc = (text_addr + i + 4) & ~1
        if (pc + imm) in (target, t1):
            out.append(text_addr + i)
    return out


def main() -> int:
    elf, sym = sys.argv[1], sys.argv[2]
    secs = sections(elf)
    print(f"elf    : {elf}")
    print(f"symbol : {sym}")

    stub = plt_stub(secs, elf, sym)
    if stub is None:
        print("no PLT stub resolved")
        return 1
    print(f"PLT    : 0x{stub:x}  (thumb 0x{stub | 1:x})\n")

    taddr, toff, tsize = secs.get(".text", (0, 0, 0))
    if not tsize:
        print("no .text")
        return 1
    print(f".text  : 0x{taddr:x}  {tsize / 1e6:.1f} MB")

    with open(elf, "rb") as f:
        f.seek(toff)
        text = f.read(tsize)

    hits = thumb_calls(text, taddr, stub)
    print(f"\nThumb call sites: {len(hits)}")
    for h in hits[:60]:
        print(f"    0x{h:08x}")
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())