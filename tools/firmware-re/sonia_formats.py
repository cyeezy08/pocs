#!/usr/bin/env python3
"""
Resolve the format strings feeding sonia's 7 snprintf/sprintf -> system() sites.

Classification of all 9 libc system() sites in sonia (mixed ARM/Thumb PIE):

  0x1cf454  constant          'cat /proc/meminfo'
  0x1cf462  constant          'top sonia -n 1'
  0x930508  mov r0, r4        (buffer built earlier)
  0x1064188 snprintf -> system, buf r7
  0x10641b0 snprintf -> system, buf r7
  0x107f91e snprintf -> system, buf r4
  0x107f948 snprintf -> system, buf r4
  0x10aaa36 sprintf  -> system, buf r8
  0x10aba06 sprintf  -> system, buf r8

So 7 of 9 build the command at runtime. Those are the interesting ones: the
format string is a rodata literal loaded into the format argument position
(r2 for snprintf, r1 for sprintf), so resolving it means finding the literal
pool entry feeding that register immediately before the call.

Sites whose buffer is populated by an unrecognised call are reported as
unresolved rather than guessed.

CONTROL: at least one format string must resolve. Zero means the pool
arithmetic is wrong and the unresolved list is equally invalid.
"""
from __future__ import annotations

import re
import struct

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"

# site -> (format-register, call mnemonic)
SITES = {
    0x1064188: ("r2", "snprintf"),
    0x10641B0: ("r2", "snprintf"),
    0x107F91E: ("r2", "snprintf"),
    0x107F948: ("r2", "snprintf"),
    0x10AAA36: ("r1", "sprintf"),
    0x10ABA06: ("r1", "sprintf"),
    0x930508:  ("r1", "unknown"),
}


def cstr(vaddr: int, limit: int = 220) -> str:
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

    resolved, unresolved = [], []
    for site, (reg, _kind) in sorted(SITES.items()):
        target_line = None
        for i, l in enumerate(lines):
            m = re.match(rf"^\s*{site:x}:", l)
            if m:
                target_line = i
                break
        if target_line is None:
            unresolved.append((site, "site not found in disasm"))
            continue

        # walk back for ldr <reg>,[pc,...] + add <reg>,pc
        pool_val = None
        for j in range(target_line - 1, max(0, target_line - 40), -1):
            m = re.search(rf"ldr\s+{reg},\s*\[pc(?:,\s*#(\d+))?\]", lines[j])
            if not m:
                continue
            pc_l = int(lines[j].split(":")[0].strip(), 16)
            pool = ((pc_l + 4) & ~3) + (int(m.group(1)) if m.group(1) else 0)
            # confirm an 'add <reg>,pc' consumes it
            add_pc = None
            for k in range(j + 1, target_line):
                if re.search(rf"add\s+{reg},\s*pc", lines[k]):
                    add_pc = int(lines[k].split(":")[0].strip(), 16) + 4
                    break
            if add_pc is None:
                continue
            try:
                with open(SONIA, "rb") as f:
                    f.seek(pool)
                    word = struct.unpack("<I", f.read(4))[0]
            except OSError:
                continue
            pool_val = (word + add_pc) & 0xFFFFFFFF
            break

        if pool_val is None:
            unresolved.append((site, f"no literal load into {reg}"))
            continue

        s = cstr(pool_val)
        if s:
            resolved.append((site, reg, pool_val, s))
        else:
            s2 = cstr(struct.unpack("<I", open(SONIA, "rb").read(
                (lambda p: p)(0))[0:0] or b"\x00\x00\x00\x00" and 0) if False else 0) if False else ""
            unresolved.append((site, f"0x{pool_val:x} not printable"))

    print(f"=== format strings resolved: {len(resolved)}/{len(SITES)} ===\n")
    for site, reg, va, s in resolved:
        print(f"  0x{site:x}  {reg} -> 0x{va:x}  {s!r}")

    print(f"\n=== unresolved: {len(unresolved)} ===")
    for site, why in unresolved:
        print(f"  0x{site:x}  {why}")

    print("\nCONTROL:", "PASS" if resolved else "FAIL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())