#!/usr/bin/env python3
"""Find a real squashfs superblock in a firmware blob.

A four-byte magic scan is not enough. `hsqs` appears by chance in
compressed data often enough to matter, and a false hit yields a garbage
file that either fails to mount or, worse, mounts as something that
looks plausible. So validate structurally:

  - block_log sane (12..20, i.e. 4 KiB .. 1 MiB blocks)
  - compression id in the known set
  - inode count non-zero and below a plausible ceiling
  - bytes_used consistent with the containing file
  - version 3 or 4

Only offsets passing all of those are reported.

    python3 findsqfs.py <firmware.bin>
"""
import mmap
import os
import struct
import sys

COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}


def parse(d: bytes) -> dict | None:
    """Return a superblock dict if d looks structurally valid, else None."""
    if len(d) < 96 or d[:4] != b"hsqs":
        return None
    (inodes,) = struct.unpack("<I", d[4:8])
    (block_log,) = struct.unpack("<H", d[22:24])
    (comp,) = struct.unpack("<H", d[20:22])
    (flags,) = struct.unpack("<H", d[24:26])
    (no_ids,) = struct.unpack("<H", d[26:28])
    (ver,) = struct.unpack("<H", d[28:30])
    (used,) = struct.unpack("<Q", d[40:48])

    # structural gates
    if not (12 <= block_log <= 20):
        return None
    if comp not in COMP:
        return None
    if ver not in (3, 4):
        return None
    if inodes == 0 or inodes > 1_000_000:
        return None
    if no_ids == 0 or no_ids > 1_000_000:
        return None
    if used < 1 << 16:
        return None

    return {
        "inodes": inodes,
        "mkfs_time": struct.unpack("<I", d[8:12])[0],
        "block_size": 1 << block_log,
        "block_log": block_log,
        "fragments": struct.unpack("<I", d[16:20])[0],
        "compression": comp,
        "comp_name": COMP[comp],
        "flags": hex(flags),
        "no_ids": no_ids,
        "version": ver,
        "bytes_used": used,
    }


def main() -> int:
    path = sys.argv[1]
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)

        raw, valid = [], []
        off = 0
        while True:
            i = m.find(b"hsqs", off)
            if i < 0 or i + 96 > size:
                break
            raw.append(i)
            sb = parse(m[i : i + 96])
            if sb:
                sb["offset"] = i
                sb["fits"] = sb["bytes_used"] + i <= size
                valid.append(sb)
            off = i + 1

    print(f"file    : {path}  ({size / 1e6:.1f} MB)")
    print(f"magic hits: {len(raw)} at {[hex(x) for x in raw]}")
    print(f"structurally valid: {len(valid)}\n")

    for sb in valid:
        mark = "OK " if sb["fits"] else "TRUNC"
        print(f"[{mark}] offset 0x{sb['offset']:x}")
        print(f"     version     : {sb['version']}")
        print(f"     compression : {sb['comp_name']} ({sb['compression']})")
        print(f"     block_size  : {sb['block_size']}")
        print(f"     inodes      : {sb['inodes']}")
        print(f"     bytes_used  : {sb['bytes_used']} ({sb['bytes_used'] / 1e6:.1f} MB)")
        print(f"     fits in file: {sb['fits']}")
        print()

    if not valid:
        print("No structurally valid squashfs. Rootfs is likely encrypted")
        print("or uses a different container. Try unblob, or look for")
        print("encrypted volume markers around each gzip/lzma hit.")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())