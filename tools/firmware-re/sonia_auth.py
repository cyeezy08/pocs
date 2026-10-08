#!/usr/bin/env python3
"""
Answer the auth question statically: are sonia's exec sites inside an
authenticated request path?

Both the Dahua and Tenda threads are blocked on the same unknown -- whether
the system()/popen() sites are reachable before session validation. Every
call site sits in a stripped static function, so there is no symbol to
attach an auth check to. But the function body is still there, and if a
function references auth-related strings, that is evidence about which
layer it belongs to.

Method, without symbols or Ghidra:
  1. recover function boundaries by scanning backwards for a Thumb/ARM
     prologue (push {... lr} / stmfd sp!, {... lr}) and stopping at the
     preceding return
  2. inside each recovered function, resolve every Thumb literal-pool
     load (ldr rX,[pc,#imm] + add rX,pc) and read the rodata string
  3. flag auth/login/session strings among them

This is a heuristic and is reported as one. Its failure mode is a function
whose strings are loaded by a callee rather than directly, which would make
it look unauthenticated when it is not.

CONTROL: the function containing BOTH 0x1cf454 ('cat /proc/meminfo') and
0x1cf462 ('top sonia -n 1') must resolve both strings. They are 14 bytes
apart, so they are certainly the same function. If that function does not
yield both, the boundary or literal-load recovery is broken.
"""
from __future__ import annotations

import re
import struct

SONIA = "/root/fw/sd4x/rootfs/usr/bin/sonia"
ASM = "/tmp/sonia.asm"

# the exec sites to characterise, from SONIA-SYSTEM-CALLS.md and
# SONIA-OTHER-PRIMITIVES.md
SITES = {
    0x1CF454: "system('cat /proc/meminfo')",
    0x1CF462: "system('top sonia -n 1')",
    0x930508: "system('echo error > /var/sdio_status')",
    0x107F91E: "system('rm %s')",
    0x10641B0: "system('ln -s %s %s')",
    0x107F948: "system('ln -s %s %s')",
    0x10AAA36: "system('mem w ...')",
    0x10ABA06: "system('mem w ...')",
    0x1D7862: "popen(std::string*)  <-- pass-through",
    0xFAE78C: "popen('cat /proc/ax_proc/mem_cmm_info')",
}

AUTH_RX = re.compile(
    r"(login|logout|passwd|password|session|auth|token|privilege|admin|"
    r"digest|nonce|wse|wsse|credential|cookie|account|verify_author)",
    re.I,
)

PROLOGUE = re.compile(r"(push\s+\{[^}]*\blr\b|stmdb\s+sp!.*\blr\b|stmfd\s+sp!)")
RET = re.compile(r"\b(pop|bx)\s")
POOL = re.compile(r"ldr\s+r(\d+),\s*\[pc(?:,\s*#(\d+))?\]")
ADDPC = re.compile(r"add\s+r(\d+),\s*pc")


def cstr(vaddr: int, limit: int = 160) -> str:
    try:
        with open(SONIA, "rb") as f:
            f.seek(vaddr)
            raw = f.read(limit)
    except OSError:
        return ""
    for chunk in raw.split(b"\x00"):
        s = chunk.decode("utf-8", "replace")
        if 3 <= len(s) <= 140 and all(32 <= ord(c) < 127 for c in s):
            return s
    return ""


def main() -> int:
    lines = open(ASM, errors="replace").read().splitlines()

    # index: addr -> (line_index, text)
    addr_idx: dict[int, int] = {}
    ordered: list[int] = []
    for i, l in enumerate(lines):
        m = re.match(r"^\s+([0-9a-f]{4,8}):\t", l)
        if m:
            a = int(m.group(1), 16)
            addr_idx[a] = i
            ordered.append(a)
    print(f"indexed {len(addr_idx)} instructions\n")

    # prologue table: every plausible function start
    prologues: list[int] = []
    for a in ordered:
        if PROLOGUE.search(lines[addr_idx[a]]):
            prologues.append(a)
    print(f"candidate prologues: {len(prologues)}\n")

    def func_start(site: int) -> int:
        best = 0
        for p in prologues:
            if p <= site:
                best = p
            else:
                break
        return best

    def strings_in(start: int, end: int) -> list[str]:
        out: list[str] = []
        # Iterate the indexed addresses, not a raw +2 walk. Thumb and ARM32 are
        # interleaved in this binary, so consecutive addresses are not
        # consecutive instructions and a +2 step lands on addresses objdump
        # never printed (KeyError on the first one).
        window = [a for a in ordered if start <= a < end]
        for pos, i in enumerate(window):
            ln = lines[addr_idx[i]]
            m = POOL.search(ln)
            if m:
                reg, imm = m.group(1), m.group(2)
                pool = ((i + 4) & ~3) + (int(imm) if imm else 0)
                # look ahead for the matching add r<reg>,pc
                add_pc = None
                for k in window[pos + 1:]:
                    mm = ADDPC.search(lines[addr_idx[k]])
                    if mm and mm.group(1) == reg:
                        add_pc = k + 4
                        break
                if add_pc is not None:
                    try:
                        with open(SONIA, "rb") as f:
                            f.seek(pool)
                            word = struct.unpack("<I", f.read(4))[0]
                    except OSError:
                        word = 0
                    s = cstr((word + add_pc) & 0xFFFFFFFF)
                    if not s:
                        s = cstr(word)
                    if s:
                        out.append(s)
        return out

    report: dict[str, dict] = {}
    for site, desc in sorted(SITES.items()):
        if site not in addr_idx:
            print(f"  0x{site:x} NOT FOUND")
            continue
        st = func_start(site)
        # function end = next prologue
        nxt = next((p for p in prologues if p > site), site + 0x2000)
        strs = strings_in(st, nxt)
        auth = [s for s in strs if AUTH_RX.search(s)]
        report[desc] = {"site": site, "start": st, "size": nxt - st,
                        "strings": strs, "auth": auth}
        flag = "AUTH" if auth else "----"
        print(f"  [{flag}] 0x{site:x} func 0x{st:x}+0x{nxt - st:x}  {desc}")
        for s in auth[:4]:
            print(f"            auth string: {s!r}")

    # control
    print("\n=== CONTROL ===")
    k1 = "system('cat /proc/meminfo')"
    k2 = "system('top sonia -n 1')"
    if k1 in report and k2 in report:
        s1 = report[k1]["strings"]
        s2 = report[k2]["strings"]
        ok = any("cat /proc/meminfo" in x for x in s1) and \
             any("top sonia -n 1" in x for x in s2)
        print(f"  both strings recovered: {ok}")
        print(f"    0x1cf454 func strings: {s1[:6]}")
        print(f"    0x1cf462 func strings: {s2[:6]}")
        if not ok:
            print("  CONTROL FAILED -- boundary or literal-load recovery is")
            print("  broken. The auth flags above are meaningless; discard.")
    print("\nCaveat: absence of an auth string is not proof of pre-auth.")
    print("A handler may inherit the session check from a caller.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())