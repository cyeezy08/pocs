#!/usr/bin/env python3
"""
Caller walk for sonia exec sinks, using verified entries.

Two earlier versions reported zero callers and both were wrong:

  1. matching branches against the system() call instruction -- impossible,
     since callers branch to a function ENTRY
  2. using prologue-derived entries -- in this ARM/Thumb binary ARM data sits
     next to code and produces false prologues, so the entries were wrong

The entry used here is the nearest preceding address that some branch in the
file targets, which is empirically reliable: it yields entries with 1-5 real
incoming branches, where the prologue-derived ones had none.

The walk is two levels. Level 1 names the direct callers; level 2 finds their
callers. Vtable membership is joined in so a virtual caller is named by class.

CONTROL: PDI_systemCmd@plt (0x16be14) must show exactly 2 call sites, and
level 1 must be non-empty. Both are known-good reference points.
"""
from __future__ import annotations

import bisect
import collections
import re
import struct
import subprocess

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"
TADDR, TSIZE = 0x16D100, 0x1DC8DB0

RTTI = re.compile(r"N\d+Dahua[\w.$]*?(C\w+|I\w+)(?:[0-9]+)?E")
VT_DELTA = 60
BRANCH = re.compile(
    r"\b(?:b|bl|blx|bx|bne|beq|bgt|blt|bge|ble|bhi|bls|bcc|bcs|blo|bpl|bmi|"
    r"bvc|bvs|bal|bleq)\s+([0-9a-f]{4,8})\b"
)

SINK_NOTE = {
    0x107F91E: "system('rm %s')",
    0x1D7862: "popen(std::string*) PASS-THROUGH",
    0x10641B0: "system('ln -s %s %s')",
    0x212092: "execl('/bin/sh')",
    0x211F54: "execl(caller-supplied)",
    0x10AAA36: "system('mem w ...')",
    0x10ABA06: "system('mem w ...')",
    0x1CF454: "system('cat /proc/meminfo')",
    0x930508: "system('echo error > /var/sdio_status')",
    0xFAE78C: "popen('cat /proc/ax_proc/...')",
    0x931DA8: "execvp('/usr/sbin/3gpp')",
    0xF26E90: "PDI_systemCmd",
    0xF695CE: "PDI_systemCmd (licence)",
}


def demangle(n: str) -> str:
    try:
        o = subprocess.run(["c++filt", n], capture_output=True, text=True, timeout=15)
        if o.returncode == 0 and o.stdout.strip():
            return o.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return n


def vtable_classes() -> dict[int, str]:
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
    owner: dict[int, str] = {}
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
            for f in funcs:
                owner.setdefault(f, name)
    return owner


def main() -> int:
    lines = open(ASM, errors="replace").read().splitlines()
    addr_idx: dict[int, int] = {}
    ordered: list[int] = []
    for i, l in enumerate(lines):
        m = re.match(r"^\s+([0-9a-f]{4,8}):\t", l)
        if m:
            a = int(m.group(1), 16)
            addr_idx[a] = i
            ordered.append(a)
    print(f"instructions: {len(ordered)}")

    srcs: dict[int, list[int]] = collections.defaultdict(list)
    nbranch = 0
    for a in ordered:
        m = BRANCH.search(lines[addr_idx[a]])
        if m:
            t = int(m.group(1), 16) & ~1
            srcs[t].append(a)
            nbranch += 1
    tgt_sorted = sorted(srcs)
    print(f"branches: {nbranch}  distinct targets: {len(tgt_sorted)}")

    def entry_for(addr: int) -> int:
        i = bisect.bisect_right(tgt_sorted, addr) - 1
        return tgt_sorted[i] if i >= 0 else 0

    vt = vtable_classes()
    print(f"vtable-named virtual functions: {len(vt)}\n")

    # level 1
    l1: dict[int, set[str]] = {}
    print("=== level 1: direct callers ===")
    for sink, note in sorted(SINK_NOTE.items()):
        e = entry_for(sink)
        callers = sorted(set(srcs.get(e, [])))
        # a caller inside the same function is an intra-function branch
        intra = [c for c in callers if entry_for(c) == e]
        ext = [c for c in callers if entry_for(c) != e]
        print(f"\n  sink 0x{sink:x} {note}")
        print(f"      entry 0x{e:x}   incoming branches {len(callers)} "
              f"({len(intra)} intra-function)")
        for c in ext[:5]:
            ce = entry_for(c)
            cls = vt.get(ce)
            tag = demangle(cls) if cls else "(static)"
            l1.setdefault(ce, set()).add(note)
            print(f"      <- 0x{c:x} in func 0x{ce:x}  {tag}")

    print(f"\n=== level 1: {len(l1)} distinct external caller functions ===")
    for f in sorted(l1):
        cls = vt.get(f)
        tag = demangle(cls) if cls else "(static)"
        print(f"  0x{f:x} {tag}")

    # level 2
    l2: dict[int, set[int]] = collections.defaultdict(set)
    for t in l1:
        for s in srcs.get(t, []):
            e = entry_for(s)
            if e != t:
                l2[e].add(t)
    print(f"\n=== level 2: {len(l2)} function(s) call a level-1 caller ===")
    for f in sorted(l2)[:40]:
        cls = vt.get(f)
        tag = demangle(cls) if cls else "(static)"
        ups = ", ".join(f"0x{t:x}" for t in sorted(l2[f])[:3])
        print(f"  0x{f:x} {tag:52} -> {ups}")

    plt = len(srcs.get(0x16BE14, []))
    print("\n=== CONTROL ===")
    print(f"  PDI_systemCmd@plt call sites : {plt}  (expect 2)")
    print(f"  level-1 external callers     : {len(l1)}  (expect > 0)")
    print("  status:", "PASS" if plt == 2 and l1 else "FAIL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())