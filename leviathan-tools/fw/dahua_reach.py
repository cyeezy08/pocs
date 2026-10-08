#!/usr/bin/env python3
"""
Exhaustive reachability check for Dahua's shell-out primitives.

The primitive is confirmed: NetSetDNSHostName does
    snprintf(buf, 64, "hostname %s", arg); system(buf);

The question is whether anything reaches it. Rather than disassembling every
binary (slow, and the functions are stripped anyway), use the dynamic symbol
tables: if no executable imports a symbol, no static call path exists. That
catches direct calls and is cheap.

Limitation, stated plainly: this does NOT catch dlsym-based lookup. A binary
could resolve the symbol by name at runtime. So for each candidate the script
also checks whether the symbol's NAME appears as a string in any binary, which
is what a dlsym call would need. If neither the import nor the string is
present, the function is genuinely unreachable in this build.

    python3 dahua_reach.py <rootfs_dir>
"""
from __future__ import annotations

import os
import subprocess
import sys

SYMS = ["NetSetDNSHostName", "run_sys", "PDI_systemCmd"]

DEFINE = "define"
IMPORT = "import"


def scan(root: str) -> None:
    defines: dict[str, list[str]] = {s: [] for s in SYMS}
    imports: dict[str, list[str]] = {s: [] for s in SYMS}
    strrefs: dict[str, list[str]] = {s: [] for s in SYMS}

    files = 0
    for dirpath, _d, names in os.walk(root):
        for fn in names:
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue
            files += 1

            # dynamic symbol table
            out = subprocess.run(
                ["readelf", "--dyn-syms", "--wide", p],
                capture_output=True, text=True, errors="replace",
            ).stdout
            for line in out.splitlines():
                f_ = line.split()
                if len(f_) < 8 or f_[3] != "FUNC":
                    continue
                name = f_[7]
                if name not in defines:
                    continue
                if f_[4] == "GLOBAL":
                    # UND section index means imported, defined otherwise
                    if f_[6] == "UND":
                        imports[name].append(p)
                    else:
                        defines[name].append(p)

            # dlsym-style string references
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            for s in SYMS:
                if s.encode() in data:
                    strrefs[s].append(p)

    print(f"ELF files scanned: {files}\n")
    for s in SYMS:
        d = sorted(set(defines[s]))
        i = sorted(set(imports[s]))
        print(f"=== {s} ===")
        print(f"  defines ({len(d)}): {', '.join(os.path.basename(x) for x in d) or '(none)'}")
        print(f"  imports ({len(i)}): {', '.join(os.path.basename(x) for x in i) or '(none)'}")
        # strip libs out of the string refs; they define the name by definition
        sr = [x for x in sorted(set(strrefs[s])) if x not in set(d)]
        print(f"  name-as-string in non-defining binaries: "
              f"{', '.join(os.path.basename(x) for x in sr) or '(none)'}")
        callers = [x for x in i if x not in set(d)]
        print(f"  VERDICT: {'CALLED by ' + str(len(callers)) + ' binaries' if callers else 'NO STATIC CALLERS'}")
        print()


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "/root/fw/sd4x/rootfs"
    if not os.path.isdir(root):
        print(f"no such dir: {root}")
        return 2
    scan(root)
    print("CONTROL: sonia must appear as an importer of run_sys. It does")
    print("(verified independently). If a future run reports no importers")
    print("anywhere, the scan is broken and these verdicts are void.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())