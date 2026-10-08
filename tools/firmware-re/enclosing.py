#!/usr/bin/env python3
"""Map a call address to its nearest preceding exported symbol.

sonia is stripped of local symbols but still carries 1300-odd GLOBAL FUNC
entries, enough to name the regions a call site falls in. Prints the symbol,
the offset into it, and whether the nearest preceding symbol looks like a
daemon/HTTP entry point rather than a std::string helper.

    python3 enclosing.py <addr> [addr ...]
"""
import re
import sys

ASM = "/tmp/sonia.asm"
SYM = re.compile(r"^([0-9a-f]+)\s+<([^>]+)>:")
CALL = re.compile(r"^\s*([0-9a-f]+):")

# Names that suggest request-handling rather than library plumbing.
INTERESTING = re.compile(
    r"(http|api|handler|server|request|dispatch|process|service|daemon|main|"
    r"recv|handle|serve|cmd|command|task|job|exec|shell|cli|entry)",
    re.I,
)
BORING = re.compile(r"(std::|__gnu_cxx|operator|basic_|<Unwind|_ZN|_ZS|_ZT)", re.I)


def main() -> int:
    targets = sorted(int(a, 16) for a in sys.argv[1:])
    if not targets or not ASM:
        print(__doc__)
        return 2

    # one pass: build a sorted list of (addr, name) label starts
    labels: list[tuple[int, str]] = []
    for line in open(ASM, errors="replace"):
        m = SYM.match(line)
        if m:
            labels.append((int(m.group(1), 16), m.group(2)))

    import bisect
    addrs = [a for a, _ in labels]

    print(f"{len(labels)} symbol labels loaded\n")
    for t in targets:
        i = bisect.bisect_right(addrs, t) - 1
        if i < 0:
            print(f"0x{t:x}  <before first symbol>")
            continue
        base, name = labels[i]
        off = t - base
        tag = ""
        if INTERESTING.search(name) and not BORING.search(name):
            tag = "  <== looks like a handler"
        elif BORING.search(name):
            tag = "  (C++ library code)"
        print(f"0x{t:x}  {name}  +0x{off:x}{tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())