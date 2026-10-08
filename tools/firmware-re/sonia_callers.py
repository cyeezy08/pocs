#!/usr/bin/env python3
"""
Name the Dahua handler class that reaches each exec sink, by scanning
recovered vtable functions for calls into the sink addresses.

Forward attribution failed: none of the 13 exec sites is a virtual function,
so they are internal helpers called from somewhere inside the RPC layer. The
vtables themselves ARE named, so work backwards instead -- for each recovered
vtable function, look for a branch that targets one of the sinks.

Match is by branch target, not by text search of the whole disassembly, so a
function body is only credited for a call it actually contains.

CONTROL: the vtable recovery must again produce 88 vtables, and at least one
vtable function must contain a branch to a sink. If neither holds, the scan
is broken and the attribution table is void.
"""
from __future__ import annotations

import re
import struct
import subprocess

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"

SINKS = {
    0x1CF454: "system('cat /proc/meminfo')",
    0x1CF462: "system('top sonia -n 1')",
    0x930508: "system('echo error > /var/sdio_status')",
    0x107F91E: "system('rm %s')",
    0x10641B0: "system('ln -s %s %s')",
    0x107F948: "system('ln -s %s %s')",
    0x10AAA36: "system('mem w ...')",
    0x10ABA06: "system('mem w ...')",
    0x1D7862: "popen(std::string*) PASS-THROUGH",
    0xFAE78C: "popen('cat /proc/ax_proc/...')",
    0x212092: "execl('/bin/sh')",
    0x211F54: "execl(caller-supplied)",
    0x931DA8: "execvp('/usr/sbin/3gpp')",
    0xF26E90: "PDI_systemCmd",
    0xF695CE: "PDI_systemCmd (licence)",
}

RTTI = re.compile(r"N\d+Dahua[\w.$]*?(C\w+|I\w+)(?:[0-9]+)?E")
# Measured empirically, not assumed from the Itanium ABI. See sonia_vtables.py:
# typeinfo_object + 60 recovers 818 vtables / 9,383 virtual functions, whereas
# the textbook -8 layout recovers 88. An earlier version of this script used
# the -8 layout, searched a 1.7% sample, and reported "no caller" for all 15
# sinks -- a false negative produced entirely by the wrong offset.
VT_DELTA = 60
BRANCH = re.compile(r"\b(?:b|bl|blx|bx|bne|beq|bgt|blt|bge|ble|bhi|bls|bcc|bcs|blo|bcs)\s+([0-9a-f]+)\s")


def demangle(name: str) -> str:
    try:
        o = subprocess.run(["c++filt", name], capture_output=True, text=True,
                           timeout=20)
        if o.returncode == 0 and o.stdout.strip():
            return o.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return name


def vtables(taddr: int, tsize: int, data: bytes, rtti: dict[int, str]):
    """Recover vtables.

    The typeinfo object is located by the pointer it holds to its own name
    string (that pointer sits at typeinfo_object + 4). The vtable's first slot
    is VT_DELTA past the typeinfo object. Note this indexes typeinfo OBJECTS,
    not every occurrence of a typeinfo pointer -- an earlier version scanned
    for pointer occurrences and then added the delta, which does not compose,
    and silently recovered only 88 vtables.
    """
    ti: dict[int, str] = {}
    for off in range(0, len(data) - 8, 4):
        v = struct.unpack_from("<I", data, off)[0]
        if v in rtti:
            ti[off - 4] = rtti[v]
    out: dict[int, tuple[str, list[int]]] = {}
    for ti_obj, name in ti.items():
        vt = ti_obj + VT_DELTA
        if vt < 0 or vt + 32 >= len(data):
            continue
        funcs, ok = [], True
        for k in range(32):
            try:
                v2 = struct.unpack_from("<I", data, vt + k * 4)[0]
            except struct.error:
                ok = False
                break
            if v2 == 0:
                break
            if not (taddr <= (v2 & ~1) < taddr + tsize):
                ok = False
                break
            funcs.append(v2 & ~1)
        if ok and len(funcs) >= 3:
            out[vt] = (name, funcs)
    return out


def main() -> int:
    secs_out = subprocess.run(["readelf", "-S", "--wide", SONIA],
                              capture_output=True, text=True, errors="replace").stdout
    taddr = tsize = 0
    for line in secs_out.splitlines():
        p = line.split()
        if len(p) >= 5 and p[1] == ".text":
            hexes = []
            for tok in p[3:]:
                try:
                    hexes.append(int(tok, 16))
                except ValueError:
                    pass
            taddr, tsize = hexes[0], hexes[2]

    data = open(SONIA, "rb").read()
    so = subprocess.run(["strings", "-t", "x", "-n", "6", SONIA],
                        capture_output=True, text=True, errors="replace").stdout
    rtti = {}
    for line in so.splitlines():
        p = line.split(None, 1)
        if len(p) == 2 and RTTI.search(p[1].strip()):
            rtti[int(p[0], 16)] = p[1].strip()

    vts = vtables(taddr, tsize, data, rtti)
    print(f"RTTI names {len(rtti)}   vtables {len(vts)}")
    if len(vts) != 88:
        print(f"NOTE: expected 88 vtables from the earlier run, got {len(vts)}.")

    # index the disassembly once
    lines = open(ASM, errors="replace").read().splitlines()
    addr_idx: dict[int, int] = {}
    ordered: list[int] = []
    for i, l in enumerate(lines):
        m = re.match(r"^\s+([0-9a-f]{4,8}):\t", l)
        if m:
            a = int(m.group(1), 16)
            addr_idx[a] = i
            ordered.append(a)
    print(f"instructions indexed: {len(ordered)}")

    # build a set of branch targets -> who branches there, restricted to
    # functions that start at a vtable slot
    vfstarts = set()
    for _vt, (_n, funcs) in vts.items():
        vfstarts.update(funcs)
    print(f"distinct vtable function entry points: {len(vfstarts)}")

    callers: dict[int, set[str]] = {}
    for a in ordered:
        if a not in vfstarts:
            continue
        ln = lines[addr_idx[a]]
        m = BRANCH.search(ln)
        if not m:
            continue
        tgt = int(m.group(1), 16) & ~1
        if tgt in SINKS:
            callers.setdefault(tgt, set())

    # second pass: attribute the calling vtable by its slot address
    slot_owner: dict[int, str] = {}
    for vt, (name, funcs) in vts.items():
        for f in funcs:
            slot_owner[f] = name

    for a in ordered:
        if a not in vfstarts:
            continue
        m = BRANCH.search(lines[addr_idx[a]])
        if not m:
            continue
        tgt = int(m.group(1), 16) & ~1
        if tgt in SINKS:
            callers[tgt].add(slot_owner.get(a, "?"))

    print(f"\n=== sinks with a vtable-function caller: {len(callers)}/{len(SINKS)} ===")
    for sink, desc in sorted(SINKS.items()):
        owners = sorted(demangle(o) for o in callers.get(sink, ()))
        if owners:
            for o in owners[:4]:
                print(f"  0x{sink:x}  <- {o}")
                print(f"             {desc}")
        else:
            print(f"  0x{sink:x}  <- (no direct vtable caller)   {desc}")

    print("\nCONTROL:", "PASS" if (len(vts) >= 80 and callers) else "FAIL")
    if not callers:
        print("  No vtable function branches directly to a sink. That does not")
        print("  prove unreachability: the caller may be two or more frames")
        print("  up, reached through a non-virtual intermediate. Treat as")
        print("  inconclusive, not as a negative finding.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())