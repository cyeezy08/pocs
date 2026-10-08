#!/usr/bin/env python3
"""
Direct-call caller walk for sonia's exec-bearing functions, done correctly.

The earlier attempt matched branches against the address of the system() call
instruction. That can never match, because callers branch to a function's
ENTRY, not to an instruction in its middle. With zero matches the tool looked
like it had proved unreachability; the control caught it.

This version branches against entry points. It also fixes the function
boundary recovery: the previous one treated every prologue-looking instruction
as a function start, and ARM data regions next to code produce false
prologues. Boundaries are instead derived per-function by walking back from
the sink to the nearest prologue AND verifying that the candidate entry
actually has branches pointing at it.

    python3 sonia_direct_callers.py
"""
from __future__ import annotations

import bisect
import collections
import re

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"

# entry point -> what it does
BEARERS = {
    0x107F0C8: "system('rm %s'), system('ln -s %s %s')",
    0x1063644: "system('ln -s %s %s')",
    0x1D7836: "popen(std::string*)  PASS-THROUGH",
    0xFAE754: "popen('cat /proc/ax_proc/mem_cmm_info')",
    0x1CF3C0: "system('cat /proc/meminfo'), system('top sonia -n 1')",
    0x93047C: "system('echo error > /var/sdio_status')",
    0x10AA590: "system('mem w ...')",
    0x10AB560: "system('mem w ...')",
}

BRANCH = re.compile(
    r"\b(?:b|bl|blx|bx|bne|beq|bgt|blt|bge|ble|bhi|bls|bcc|bcs|blo|bpl|bmi|"
    r"bvc|bvs|bal|bleq|bls)\s+([0-9a-f]{4,8})\b"
)
PROLOGUE = re.compile(r"(push\s+\{[^}]*\blr\b|stmdb\s+sp!|stmfd\s+sp!)")


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
    n = len(ordered)
    print(f"instructions indexed: {n}")

    # call graph: target -> set of source addresses
    targets_of: dict[int, set[int]] = collections.defaultdict(set)
    sources: dict[int, list[int]] = collections.defaultdict(list)
    nbranch = 0
    for a in ordered:
        m = BRANCH.search(lines[addr_idx[a]])
        if not m:
            continue
        t = int(m.group(1), 16) & ~1
        targets_of[t].add(a)
        sources[t].append(a)
        nbranch += 1
    print(f"branches matched: {nbranch}   distinct targets: {len(targets_of)}")

    # candidate function entries = prologue addresses that something branches to
    # (an entry nobody calls is either dead or a mis-detected boundary)
    pro = [a for a in ordered if PROLOGUE.search(lines[addr_idx[a]])]
    called = set(targets_of)
    entries = [a for a in pro if a in called]
    print(f"prologues {len(pro)}, of which targeted by a branch: {len(entries)}")

    import bisect as _b
    ent = entries

    def func_of(addr: int) -> int:
        i = _b.bisect_right(ent, addr) - 1
        return ent[i] if i >= 0 else 0

    # level 1: functions with a branch to a bearer entry
    print(f"\n=== level 1: direct callers of each exec-bearing function ===")
    l1: dict[int, set[str]] = {}
    for entry, note in sorted(BEARERS.items()):
        srcs = sources.get(entry, [])
        callers = collections.Counter(func_of(s) for s in srcs)
        callers.pop(entry, None)
        print(f"\n  0x{entry:x}  {note}")
        if not callers:
            print("      no direct bl/blx found")
            continue
        for f, c in callers.most_common(6):
            l1.setdefault(f, set()).add(note)
            print(f"      called by 0x{f:x}  ({c} site(s))")

    print(f"\n=== level 1 summary: {len(l1)} distinct caller function(s) ===")

    # control: a PLT entry we know is called
    plt_check = sources.get(0x16BE14, [])
    print("\n=== CONTROL ===")
    print(f"  PDI_systemCmd@plt 0x16be14 call sites: {len(plt_check)}")
    print(f"  level-1 callers found: {len(l1)}")
    ok = len(plt_check) == 2 and len(l1) > 0
    print("  status:", "PASS" if ok else "FAIL")
    if not ok:
        print("  Expected exactly 2 branches to the known-called PLT stub, then")
        print("  at least one caller. Otherwise branch matching or boundary")
        print("  recovery is still wrong.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())