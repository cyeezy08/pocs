#!/usr/bin/env python3
"""
Attribute sonia's exec sites to Dahua manager classes using RTTI.

The binary is stripped of local symbols but keeps 4,310 mangled RTTI typeinfo
names (N5Dahua7Manager11CConsoleImpE and friends) plus their vtables. A vtable
entry points at a function, and each vtable sits in a section whose name is
the class's, so exec sites can be attributed to a handler class even though
the functions themselves have no symbols.

This is the missing link: knowing that 0x1d7862's popen() lives in CConsoleImp
or CUpgraderImp turns "somewhere in the web server" into a named RPC handler,
which is a claim a report can actually make.

Method:
  1. locate each RTTI typeinfo string and its typeinfo pointer
  2. find the vtable that references that typeinfo (second slot of the
     vtable points at the typeinfo object, per the Itanium ABI)
  3. for each vtable, record the function addresses in its slots
  4. intersect those with the exec call sites

CONTROL: vtable detection must find at least one vtable whose slot[0] is a
code address inside .text and whose typeinfo slot resolves to a known Dahua
mangled name. If zero such vtables are found, the parse is wrong and no
attribution may be reported.

    python3 sonia_rtti.py
"""
from __future__ import annotations

import re
import struct
import subprocess

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"

SITES = [
    (0x1CF454, "system('cat /proc/meminfo')"),
    (0x1CF462, "system('top sonia -n 1')"),
    (0x930508, "system('echo error > /var/sdio_status')"),
    (0x107F91E, "system('rm %s')"),
    (0x10641B0, "system('ln -s %s %s')"),
    (0x107F948, "system('ln -s %s %s')"),
    (0x10AAA36, "system('mem w ...')"),
    (0x10ABA06, "system('mem w ...')"),
    (0x1D7862, "popen(std::string*)  PASS-THROUGH"),
    (0xFAE78C, "popen('cat /proc/ax_proc/mem_cmm_info')"),
    (0x212092, "execl('/bin/sh')"),
    (0xF26E90, "PDI_systemCmd"),
    (0xF695CE, "PDI_systemCmd (licence path)"),
]

RTTI = re.compile(r"N\d+Dahua[\w.]*?(C\w+|I\w+)(?:[0-9]+)?E$")


def demangle(name: str) -> str:
    try:
        out = subprocess.run(["c++filt", name], capture_output=True, text=True,
                             errors="replace", timeout=20)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return name


def sections() -> dict[str, tuple[int, int, int]]:
    out = subprocess.run(["readelf", "-S", "--wide", SONIA],
                         capture_output=True, text=True, errors="replace").stdout
    secs = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) < 6 or not p[0].startswith("["):
            continue
        hexes = []
        for tok in p[3:]:
            try:
                hexes.append(int(tok, 16))
            except ValueError:
                pass
        if len(hexes) >= 3:
            secs[p[1]] = (hexes[0], hexes[1], hexes[2])
    return secs


def main() -> int:
    secs = sections()
    taddr, toff, tsize = secs.get(".text", (0, 0, 0))
    daddr, doff, dsize = secs.get(".data.rel.ro", secs.get(".data", (0, 0, 0)))
    print(f".text      0x{taddr:x} size 0x{tsize:x}")
    print(f".data.rel.ro 0x{daddr:x} size 0x{dsize:x}")

    data = open(SONIA, "rb").read()

    # 1. typeinfo strings in .rodata
    strings_out = subprocess.run(["strings", "-t", "x", "-n", "6", SONIA],
                                 capture_output=True, text=True, errors="replace").stdout
    rtti: dict[int, str] = {}
    for line in strings_out.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        m = RTTI.search(parts[1].strip())
        if m:
            rtti[int(parts[0], 16)] = parts[1].strip()
    print(f"\nDahua RTTI names: {len(rtti)}")

    # 2. typeinfo objects: a pointer to the name string sits at offset 4
    #    within a typeinfo object. Scanning the whole 44MB file once per
    #    RTTI name is O(n*m) and timed out. Instead walk the file once and
    #    look each candidate offset against the name set.
    name_by_addr = rtti
    ti_ptr: dict[int, str] = {}
    for off in range(0, len(data) - 8, 4):
        val = struct.unpack_from("<I", data, off)[0]
        nm = name_by_addr.get(val)
        if nm is not None:
            ti_ptr[off - 4] = nm
    print(f"typeinfo objects referenced: {len(ti_ptr)}")

    # 3. vtables: an array whose preceding slot is a typeinfo pointer
    ti_set = set(ti_ptr)
    vtables: dict[int, tuple[str, list[int]]] = {}
    for i in range(0, len(data) - 4, 4):
        val = struct.unpack_from("<I", data, i)[0]
        if val not in ti_set:
            continue
        vt = i + 4           # vtable starts right after the typeinfo slot
        funcs = []
        ok = True
        for k in range(0, 16):
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
            vtables[vt] = (ti_ptr[val], funcs)

    print(f"vtables recovered: {len(vtables)}")
    ctrl = [ (v,n) for v,(n,_f) in vtables.items() if any(nv==n for nv in rtti.values()) ]
    print(f"  (vtables naming a known Dahua type: {len(ctrl)})")

    # 4. attribute exec sites
    site_set = {a: d for a, d in SITES}
    print("\n=== exec sites attributed to a Dahua class ===")
    found_any = False
    for site, desc in SITES:
        owners = []
        for vt, (name, funcs) in vtables.items():
            if site in funcs:
                owners.append(name)
        if owners:
            found_any = True
            uniq = sorted(set(owners))
            for n in uniq[:3]:
                print(f"  0x{site:x}  {demangle(n):60}  {desc}")
        else:
            print(f"  0x{site:x}  {'(no vtable match)':60}  {desc}")

    print("\nCONTROL:", "PASS" if vtables and found_any else
          ("FAIL - no vtables" if not vtables else "FAIL - no site matched"))
    if not vtables:
        print("  Vtable parse is wrong; discard all attribution above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())