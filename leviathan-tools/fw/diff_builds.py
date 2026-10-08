#!/usr/bin/env python3
"""
Classify what actually changed between Tenda 5G03 firmware builds.

Two builds were pulled from the vendor's own CDN:
  V05.03.01.19  (V1.0, hardware the six Deferred CVEs name)
  V05.03.01.26  (V1.1, current release)

Both unpack to a 4,212-file rootfs. diff -rq reports ~871 differing
entries, but that number conflates opkg .control metadata (rebuild
timestamps) with real code changes. The question that matters is
narrower: did the HTTP server change at all?

Result so far: /usr/sbin/httpd has an identical MD5 across both builds.

This script separates real content changes from metadata and reports
which changed binaries matter.

    python3 diff_builds.py <old_rootfs> <new_rootfs>
"""
from __future__ import annotations

import hashlib
import os
import sys


def md5(path: str) -> str | None:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def walk(root: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            # skip device nodes and symlinks; only regular files carry content
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            out[rel] = md5(p) or ""
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    old_root, new_root = sys.argv[1], sys.argv[2]

    old = walk(old_root)
    new = walk(new_root)
    print(f"old: {len(old)} files   new: {len(new)} files")

    only_old = sorted(set(old) - set(new))
    only_new = sorted(set(new) - set(old))
    changed = sorted(k for k in set(old) & set(new) if old[k] != new[k])

    print(f"\nonly in old : {len(only_old)}")
    for k in only_old[:10]:
        print(f"    - {k}")
    print(f"only in new : {len(only_new)}")
    for k in only_new[:10]:
        print(f"    + {k}")
    print(f"changed     : {len(changed)}")

    # split changed into opkg metadata vs real content
    meta = [k for k in changed if "/opkg/info/" in k or k.endswith(".control")]
    real = [k for k in changed if k not in set(meta)]
    print(f"\n  opkg metadata (build stamps) : {len(meta)}")
    print(f"  real content changes         : {len(real)}")
    for k in real:
        print(f"      {k}")

    # the actual question
    print("\n=== web-facing binaries ===")
    web = [k for k in set(old) & set(new)
           if any(t in k for t in ("httpd", "uhttpd", "lighttpd", "nginx", "/www/", "cgi", "webui"))]
    unchanged = [k for k in web if old[k] == new[k]]
    print(f"  web-related files: {len(web)}")
    print(f"  UNCHANGED across both builds: {len(unchanged)}")
    for k in sorted(web):
        same = old[k] == new[k]
        print(f"    {'SAME  ' if same else 'DIFFER'}  {k}")

    print("\nCONTROL: the vendor bumped the version and the build date, so")
    print("something must differ. If every web binary is SAME, that is the")
    print("finding: the release changed the modem/Quectel layer, not the")
    print("HTTP server that carries the CVE sinks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())