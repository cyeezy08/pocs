#!/usr/bin/env python3
"""
Find call sites for a PLT stub inside a stripped ARM PIE.

Derives the stub address from .rel.plt (offset -> PLT index), then scans
.text for BL instructions targeting it. Handles two encodings:

  ARM  (A32)  BL  : cond 1011 imm24              -> byte offset from PC
  Thumb (T32)  BL  : 11110 S imm10 | 11 J1 1 J2 imm11

Mixed ARM/Thumb binaries are normal in camera firmware, so the section is
scanned both ways and Thumb results are reported separately.

Why not just disassemble: a 44 MB stripped binary takes tens of minutes to
import. Raw pattern scanning over .text is seconds.

    python3 pltcalls.py <elf> <symbol>
"""
from __future__ import annotations

import struct
import subprocess
import sys


def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, errors="replace").stdout


def dynsym_index(elf: str, name: str) -> int | None:
    for line in sh("readelf", "--dyn-syms", "--wide", elf).splitlines():
        if ":" not in line:
            continue
        p = line.split()
        if len(p) >= 8 and p[7] == name:
            try:
                return int(p[0].rstrip(":"))
            except ValueError:
                return None
    return None


def section(elf: str, name: str) -> tuple[int, int, int]:
    """(vaddr, file_offset, size) for a section."""
    out = sh("readelf", "-S", "--wide", elf)
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if f" {name} " in line or line.strip().endswith(name):
            m = re_search(line)
            if m:
                return m
            if i + 1 < len(lines) and "addr" not in line:
                m2 = re_search(lines[i + 1])
                if m2:
                    return m2
    return (0, 0, 0)


def re_search(line: str):
    import re
    m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
    if not m:
        return None
    addr, off, size = int(m.group(3), 16), int(m.group(4), 16), int(m.group(5), 16)
    return (addr, off, size)


def plt_stub(elf: str, sym: str) -> int | None:
    idx = dynsym_index(elf, sym)
    if idx is None:
        return None
    rel_addr, rel_off, rel_size = section(elf, ".rel.plt")
    plt_addr, _, _ = section(elf, ".plt")
    if not rel_size:
        return None
    with open(elf, "rb") as f:
        f.seek(rel_off)
        rel = f.read(rel_size)
    for i in range(rel_size // 8):
        r_off, r_info = struct.unpack("<II", rel[i * 8 : i * 8 + 8])
        if (r_info >> 8) == idx:
            return plt_addr + 20 + i * 12
    return None


def scan(elf: str, target: int) -> tuple[list[int], list[int]]:
    """Return (arm_call_sites, thumb_call_sites)."""
    taddr, toff, tsize = section(elf, ".text")
    if not tsize:
        return [], []
    with open(elf, "rb") as f:
        f.seek(toff)
        text = f.read(tsize)

    arm, thumb = [], []
    t_odd = target | 1

    # ARM BL: xxxx 1011 xxxxxxxxxxxxxxxxxxxxxxxx
    for i in range(0, len(text) - 3):
        w = struct.unpack_from("<I", text, i)[0]
        if (w >> 24) & 0xFF != 0xEB:
            continue
        imm = w & 0x00FFFFFF
        if imm & 0x800000:
            imm -= 0x1000000
        dst = (taddr + i + 8) + (imm << 2)
        if dst in (target, t_odd):
            arm.append(taddr + i)

    # Thumb BL (32-bit): 11110 S imm10 11 J1 1 J2 imm11
    for i in range(0, len(text) - 3, 2):
        hi, lo = struct.unpack_from("<HH", text, i)
        if (hi & 0xF800) != 0xF000:
            continue
        if (lo & 0xD000) != 0xD000:
            continue
        s = (hi >> 10) & 1
        imm10 = hi & 0x03FF
        j1 = (lo >> 13) & 1
        j2 = (lo >> 11) & 1
        imm11 = lo & 0x07FF
        i1 = ~(j1 ^ s) & 1
        i2 = ~(j2 ^ s) & 1
        imm = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
        if s:
            imm -= 1 << 25
        pc = (taddr + i + 4) & ~1
        dst = pc + imm
        if dst in (target, t_odd, target & ~1):
            thumb.append(taddr + i)

    return arm, thumb


def main() -> int:
    elf, sym = sys.argv[1], sys.argv[2]
    print(f"elf    : {elf}")
    print(f"symbol : {sym}")

    stub = plt_stub(elf, sym)
    if stub is None:
        print("could not resolve a PLT stub for this symbol")
        return 1
    print(f"PLT    : 0x{stub:x}\n")

    arm, thumb = scan(elf, stub)
    total = len(arm) + len(thumb)
    print(f"A32 call sites : {len(arm)}")
    for a in arm[:40]:
        print(f"    0x{a:08x}")
    print(f"\nThumb call sites: {len(thumb)}")
    for t in thumb[:40]:
        print(f"    0x{t:08x}")
    print(f"\ntotal: {total}")
    return 0 if total else 1


if __name__ == "__main__":
    raise SystemExit(main())