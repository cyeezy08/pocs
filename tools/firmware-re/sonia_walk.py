#!/usr/bin/env python3
"""
Two-level caller walk for sonia's exec sinks.

The previous scan only looked for branches to a sink from vtable entry
points. That is the wrong search space: a sink can be reached from any
static helper, not just from a virtual function. What identifies a caller is
simply "some function contains a branch whose target is the sink".

So do that over the whole of .text:

  level 0  the sink itself
  level 1  every function containing a branch to a sink
  level 2  every function containing a branch to a level-1 function

Function boundaries are recovered from Thumb/ARM prologues, which is
approximate -- a computed jump or a naked thumb function can break it. That
is why level 1 is reported per-function with its own start address, so a
reviewer can check the boundary rather than trust it.

Attribution at each level: if a caller is a known virtual function entry
point, name its class. Otherwise report the address and let the RTTI map
speak if it can.

CONTROL: level 1 must be non-empty. It was empty in the prior scan, but that
scan searched only 826 vtable entries rather than all of .text, so a non-empty
level 1 here is the expected result and its absence would mean the branch
matcher is broken. Independently, a count of branch instructions matched over
the whole file is printed as a second check.
"""
from __future__ import annotations

import re
import struct
import subprocess
import collections

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
VT_DELTA = 60

# Any conditional/unconditional branch with an explicit numeric target.
BRANCH = re.compile(
    r"\b(?:b|bl|blx|bx|bne|beq|bgt|blt|bge|ble|bhi|bls|bcc|bcs|blo|bpl|bmi|"
    r"bvc|bvs|bal|bvs|bleq|bgt|bge)\s+([0-9a-f]{4,8})\b"
)
PROLOGUE = re.compile(r"(push\s+\{[^}]*\blr\b|stmdb\s+sp!|stmfd\s+sp!)")


def demangle(name: str) -> str:
    try:
        o = subprocess.run(["c++filt", name], capture_output=True, text=True,
                           timeout=15)
        if o.returncode == 0 and o.stdout.strip():
            return o.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return name


def load_vtable_classes(taddr: int, tsize: int):
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
    slot_owner: dict[int, str] = {}
    nv = 0
    for tobj, name in ti.items():
        vt = tobj + VT_DELTA
        if vt < 0 or vt + 32 >= len(data):
            continue
        funcs, ok = [], True
        for k in range(32):
            v2 = struct.unpack_from("<I", data, vt + k * 4)[0]
            if v2 == 0:
                break
            if not (taddr <= (v2 & ~1) < taddr + tsize):
                ok = False
                break
            funcs.append(v2 & ~1)
        if ok and len(funcs) >= 3:
            nv += 1
            for f in funcs:
                slot_owner.setdefault(f, name)
    return slot_owner, nv, len(rtti)


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
    print(f"instructions indexed: {len(ordered)}")

    taddr, tsize = 0x16D100, 0x1DC8DB0
    slot_owner, nv, nrtti = load_vtable_classes(taddr, tsize)
    print(f"RTTI names {nrtti}   vtables {nv}   named virtual functions "
          f"{len(slot_owner)}")

    # function starts from prologues
    pro: list[int] = []
    for a in ordered:
        if PROLOGUE.search(lines[addr_idx[a]]):
            pro.append(a)
    pro_set = set(pro)
    import bisect
    print(f"prologue candidates: {len(pro)}")

    def func_of(addr: int) -> int:
        i = bisect.bisect_right(pro, addr) - 1
        return pro[i] if i >= 0 else 0

    # every branch target in the file -> branch count (control)
    edge: dict[int, set[int]] = collections.defaultdict(set)
    nbranch = 0
    for a in ordered:
        m = BRANCH.search(lines[addr_idx[a]])
        if not m:
            continue
        t = int(m.group(1), 16) & ~1
        edge[t].add(a)
        nbranch += 1
    print(f"branches matched: {nbranch}   distinct targets: {len(edge)}")

    # level 1: functions containing a branch to a sink
    l1: dict[int, set[str]] = {}
    for sink in SINKS:
        for src in edge.get(sink, ()):
            f = func_of(src)
            l1.setdefault(f, set()).add(SINKS[sink])

    print(f"\n=== LEVEL 1: {len(l1)} function(s) call a sink directly ===")
    for f in sorted(l1):
        cls = slot_owner.get(f)
        tag = demangle(cls) if cls else "(static)"
        for s in sorted(l1[f]):
            print(f"  0x{f:x}  {tag:52}  -> {s}")

    # level 2: functions calling a level-1 function
    l1set = set(l1)
    l2: dict[int, set[int]] = collections.defaultdict(set)
    for target in l1set:
        for src in edge.get(target, ()):
            f = func_of(src)
            if f != target:
                l2[f].add(target)

    print(f"\n=== LEVEL 2: {len(l2)} function(s) call a level-1 function ===")
    for f in sorted(l2)[:60]:
        cls = slot_owner.get(f)
        tag = demangle(cls) if cls else "(static)"
        ups = ", ".join(f"0x{t:x}" for t in sorted(l2[f])[:4])
        print(f"  0x{f:x}  {tag:52}  -> {ups}")

    # control
    print("\n=== CONTROL ===")
    print(f"  branches matched over whole file : {nbranch}  (>0 required)")
    print(f"  level-1 callers               : {len(l1)}  (>0 required)")
    ok = nbranch > 1000 and len(l1) > 0
    print("  status:", "PASS" if ok else "FAIL")
    if not ok:
        print("  Branch matching or the prologue-based function recovery is")
        print("  broken. Discard every attribution above.")
    else:
        named = sum(1 for f in l1 if f in slot_owner)
        print(f"\n  {named}/{len(l1)} level-1 callers are known virtual "
              f"functions and can be named by class.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())