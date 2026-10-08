#!/usr/bin/env python3
"""Carve a squashfs image out of a firmware blob at a byte offset.

    python3 carve.py <firmware.bin> <offset_hex_or_dec> <out.sqfs>

Verifies the superblock before writing, so a misaligned carve fails loudly
instead of producing a file that looks real and unmounts as garbage.
"""
import struct
import sys


def main() -> int:
    src, off_s, out = sys.argv[1], sys.argv[2], sys.argv[3]
    off = int(off_s, 0)

    with open(src, "rb") as f:
        f.seek(off)
        head = f.read(96)

    if head[:4] != b"hsqs":
        print(f"FAIL: no squashfs magic at 0x{off:x} (got {head[:4]!r})")
        print("      check the offset, and check endianness (try sqsh)")
        return 1

    be = struct.unpack("<H", head[24:26])[0]
    comp = struct.unpack("<H", head[20:22])[0]
    used = struct.unpack("<Q", head[40:48])[0]
    ver = struct.unpack("<H", head[28:30])[0]
    names = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}

    print(f"magic        : hsqs  OK")
    print(f"version      : {ver}")
    print(f"compression  : {comp} ({names.get(comp, 'unknown')})")
    print(f"block_size   : {1 << be}  (block_log {be})")
    print(f"bytes_used   : {used} ({used / 1e6:.1f} MB)")

    import os
    total = os.path.getsize(src)
    remaining = total - off
    n = min(used, remaining)
    print(f"carving      : {n} bytes")

    with open(src, "rb") as f, open(out, "wb") as o:
        f.seek(off)
        left = n
        while left > 0:
            chunk = f.read(min(1 << 22, left))
            if not chunk:
                break
            o.write(chunk)
            left -= len(chunk)
    print(f"wrote        : {out} ({os.path.getsize(out)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())