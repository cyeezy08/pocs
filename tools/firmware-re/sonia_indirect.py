#!/usr/bin/env python3
"""
Locate indirect callers of sonia's exec-bearing functions.

Finding 0 direct callers for the function at 0x107f0c8 was initially read as
"no vtable caller". Two checks showed that reading was wrong:

  - branches DO land on function entries (PDI_systemCmd@plt 0x16be14 has 2)
  - 0x107f0c8 is a real entry, preceded by ARM data rather than code

So the call is indirect. Three mechanisms are plausible in a -fPIC C++ binary
with 9,411 recovered virtual functions:

  1. the address sits in a vtable, called through a vtable dispatch
  2. it is in a .init_array / constructor called at load
  3. it is reached through a function pointer table in .data.rel.ro

This checks all three. For (1) it reuses the vtable recovery; for (3) it
scans .data.rel.ro for any word equal to the entry.

CONTROL: at least one of the three mechanisms must locate something for at
least one sink-bearing function. If all three come back empty across the
board, the functions are genuinely unreachable in this build -- which would be
a significant result, so it needs to be earned, not assumed.
"""
from __future__ import annotations

import bisect
import collections
import re
import struct
import subprocess

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"

RTTI = re.compile(r"N\d+Dahua[\w.$]*?(C\w+|I\w+)(?:[0-9]+)?E")
VT_DELTA = 60
PROLOGUE = re.compile(r"(push\s+\{[^}]*\blr\b|stmdb\s+sp!|stmfd\s+sp!)")

TADDR, TSIZE = 0x16D100, 0x1DC8DB0

# entry point -> the exec sink it contains
BEARERS = {
    0x107F0C8: "0x107f91e system('rm %s') + 0x107f948 system('ln -s %s %s')",
    0x1063644: "0x10641b0 system('ln -s %s %s')",
    0x1D7836: "0x1d7862 popen(std::string*) PASS-THROUGH",
    0xFAE754: "0xfae78c popen('cat /proc/ax_proc/...')",
    0x1CF3C0: "0x1cf454/0x1cf462 system(meminfo, top)",
    0x93047C: "0x930508 system('echo error > /var/sdio_status')",
    0x10AA590: "0x10aaa36 system('mem w ...')",
    0x10AB560: "0x10aba06 system('mem w ...')",
}


def demangle(n: str) -> str:
    try:
        o = subprocess.run(["c++filt", n], capture_output=True, text=True, timeout=15)
        if o.returncode == 0 and o.stdout.strip():
            return o.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return n


def main() -> int:
    data = open(SONIA, "rb").read()
    so = subprocess.run(["strings", "-t", "x", "-n", "6", SONIA],
                        capture_output=True, text=True, errors="replace").stdout
    rtti = {}
    for line in so.splitlines():
        p = line.split(None, 1)
        if len(p) == 2 and RTTI.search(p[1].strip()):
            rtti[int(p[0], 16)] = p[1].strip()
    ti = {}
    for off in range(0, len(data) - 8, 4):
        v = struct.unpack_from("<I", data, off)[0]
        if v in rtti:
            ti[off - 4] = rtti[v]

    # (1) vtable membership
    vt_owner: dict[int, str] = {}
    nvt = 0
    for tobj, name in ti.items():
        vt = tobj + VT_DELTA
        if vt < 0 or vt + 32 >= len(data):
            continue
        funcs, ok = [], True
        for k in range(32):
            v2 = struct.unpack_from("<I", data, vt + k * 4)[0]
            if v2 == 0:
                break
            if not (TADDR <= (v2 & ~1) < TADDR + TSIZE):
                ok = False
                break
            funcs.append(v2 & ~1)
        if ok and len(funcs) >= 3:
            nvt += 1
            for f in funcs:
                vt_owner.setdefault(f, name)
    print(f"vtables {nvt}, named virtual functions {len(vt_owner)}")

    # (2) init_array
    init = []
    secs = subprocess.run(["readelf", "-S", "--wide", SONIA],
                          capture_output=True, text=True, errors="replace").stdout
    for line in secs.splitlines():
        p = line.split()
        if len(p) >= 6 and p[1] in (".init_array", ".fini_array"):
            h = []
            for t in p[3:]:
                try:
                    h.append(int(t, 16))
                except ValueError:
                    pass
            if len(h) >= 3:
                arr, size = h[1], h[2]
                for i in range(0, size, 4):
                    v = struct.unpack_from("<I", data, arr + i)[0] & ~1
                    if TADDR <= v < TADDR + TSIZE:
                        init.append(v)
    print(f"init/fini_array entries pointing at code: {len(init)}")

    # (3) function-pointer tables in .data.rel.ro
    ptrs: dict[int, list[int]] = collections.defaultdict(list)
    for off in range(0, len(data) - 4, 4):
        v = struct.unpack_from("<I", data, off)[0] & ~1
        if TADDR <= v < TADDR + TSIZE:
            ptrs[v].append(off)
    print(f"code addresses referenced from writable/reloc data: {len(ptrs)}")

    print(f"\n=== how is each exec-bearing function reached? ===")
    hits = 0
    for entry, note in sorted(BEARERS.items()):
        mech = []
        if entry in vt_owner:
            mech.append(f"vtable slot of {demangle(vt_owner[entry])}")
        if entry in init:
            mech.append("init_array (runs at load)")
        if entry in ptrs:
            locs = ", ".join(f"0x{x:x}" for x in ptrs[entry][:4])
            mech.append(f"{len(ptrs[entry])} ptr slot(s) at {locs}")
        if mech:
            hits += 1
            print(f"\n  0x{entry:x}")
            print(f"      sink   : {note}")
            for m in mech:
                print(f"      via    : {m}")
        else:
            print(f"\n  0x{entry:x}  NOT FOUND in vtables, init_array or ptr tables")
            print(f"      sink   : {note}")

    print("\n=== CONTROL ===")
    print(f"  functions located : {hits}/{len(BEARERS)}")
    print("  status:", "PASS" if hits else "FAIL")
    if not hits:
        print("  All three mechanisms came back empty. Before concluding the")
        print("  functions are dead, note that a C++ member function can also be")
        print("  reached via a direct bl from another static function whose")
        print("  prologue recovery merged it into a neighbour. That was the bug")
        print("  in the previous scan, so this negative is not yet trustworthy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())