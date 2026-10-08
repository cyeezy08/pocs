#!/usr/bin/env python3
"""
Parse Openbox (OB) archive format from WhatsApp superpack.
From libsuperpack strings:
- "Bad OB header" → starts with OB magic
- "zstd_file_handler" → zstd compression
- "SP2 decompression" → SP2 format
- "Superpack version differ (library version is %d.%d.%d, archive version is %d.%d.%d)"
- "Invalid stream %d checkpoint %d, value %zu exceeds uncompressed size %zu"
- "Error reading Superpack archive (stream header) from APK"

OB container format (from Facebook's open source):
- Magic: "OB" (0x4F 0x42) or similar
- Version: 3 bytes (major, minor, patch)
- Flags
- Stream count
- Per stream: ID, UUID, compressed size, uncompressed size, data
"""

import struct
import os
import sys
import zlib
import subprocess

LIBS_SO = "/home/kali/2stage/analysis/so_files/lib/x86_64/libs.so"
OUTPUT_DIR = "/home/kali/2stage/analysis/extracted_libs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(LIBS_SO, "rb") as f:
    data = f.read()

# Symbol addresses
ARCHIVE_START = 0xc8a0
ARCHIVE_END = 0xe8be2c

archive = data[ARCHIVE_START:ARCHIVE_END]
print(f"Archive: {len(archive)} bytes (0x{len(archive):x})")

# Look for "OB" magic
ob_positions = []
pos = 0
while True:
    idx = archive.find(b'OB', pos)
    if idx < 0:
        break
    ob_positions.append(idx)
    pos = idx + 1

print(f"Found {len(ob_positions)} 'OB' occurrences")
for off in ob_positions[:10]:
    context = archive[off:off+32]
    hex_str = ' '.join(f'{b:02x}' for b in context)
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
    print(f"  0x{off:x}: {hex_str}  {ascii_str}")

# The archive might use a different magic. Let me look at the first bytes
# and try to interpret them as a header
print(f"\nFirst 128 bytes:")
for i in range(0, min(128, len(archive)), 16):
    hex_str = ' '.join(f'{b:02x}' for b in archive[i:i+16])
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in archive[i:i+16])
    print(f"  {i:04x}: {hex_str}  {ascii_str}")

# Try to find the header by looking for version-like patterns
# The version is 3 bytes: major.minor.patch
# Common versions: 1.0.0, 2.0.0, etc.
print("\n=== Looking for version patterns ===")
for i in range(0, min(1024, len(archive))):
    major, minor, patch = archive[i], archive[i+1] if i+1 < len(archive) else 0, archive[i+2] if i+2 < len(archive) else 0
    if major in [1, 2, 3] and minor == 0 and patch == 0:
        # Check if this could be a header
        before = archive[max(0,i-8):i]
        after = archive[i+3:i+32]
        print(f"  Potential version at 0x{i:x}: {major}.{minor}.{patch}")
        print(f"    Before: {' '.join(f'{b:02x}' for b in before)}")
        print(f"    After:  {' '.join(f'{b:02x}' for b in after)}")

# The archive might start with a simple header:
# [magic:2][version:3][flags:1][num_streams:2]
# Let me try different header sizes

print("\n=== Trying different header interpretations ===")
for hdr_size in [4, 8, 12, 16, 20, 24, 32]:
    if hdr_size > len(archive):
        continue
    header = archive[:hdr_size]
    print(f"\nHeader size {hdr_size}: {' '.join(f'{b:02x}' for b in header)}")

    # Try as: [num_streams:2][checkpoint_size:2][header_size:2][flags:2]
    if hdr_size >= 8:
        nstreams = struct.unpack('<H', header[0:2])[0]
        if 1 <= nstreams <= 100:
            print(f"  As (nstreams, ckpt_size, hdr_size, flags): {nstreams}")

    # Try as: [magic:4][version:4]
    if hdr_size >= 8:
        magic = struct.unpack('<I', header[0:4])[0]
        version = struct.unpack('<I', header[4:8])[0]
        print(f"  As (magic, version): 0x{magic:08x}, {version}")

# Let me try to decompress from various offsets with zstd
print("\n=== Trying zstd decompression from various offsets ===")
try:
    import zstandard as zstd
    dctx = zstd.ZstdDecompressor()

    for offset in range(0, min(4096, len(archive)), 1):
        try:
            result = dctx.decompress(archive[offset:], max_output_size=1024*1024*100)
            print(f"  SUCCESS at offset 0x{offset:x}: decompressed {len(result)} bytes")
            # Save it
            with open(os.path.join(OUTPUT_DIR, f"zstd_decompressed_0x{offset:x}.bin"), "wb") as f:
                f.write(result)
            # Check if it contains ELF
            if b'\x7fELF' in result[:1024]:
                print(f"    Contains ELF header! This might be a packed .so file")
        except Exception as e:
            pass

except ImportError:
    print("  zstandard not installed, trying other methods")

# Try with different zstd window sizes
print("\n=== Trying zstd with different parameters ===")
try:
    import zstandard as zstd
    for wlog in [0, 10, 15, 20, 25, 27]:
        try:
            dctx = zstd.ZstdDecompressor(window_size=wlog)
            result = dctx.decompress(archive[:1024*1024])
            print(f"  Window size {wlog}: decompressed {len(result)} bytes")
        except:
            pass
except:
    pass

# The archive might use a custom container with zstd-compressed chunks
# Let me look for zstd frames (magic 0x28B52FFD)
print("\n=== Scanning for zstd frames ===")
zstd_magic = b'\x28\xb5\x2f\xfd'
pos = 0
frames = []
while pos < len(archive) - 4:
    idx = archive.find(zstd_magic, pos)
    if idx < 0:
        break
    frames.append(idx)
    pos = idx + 1

print(f"Found {len(frames)} zstd frames")
for i, off in enumerate(frames[:20]):
    print(f"  Frame {i}: offset 0x{off:x} (file 0x{ARCHIVE_START+off:x})")

# Try decompressing each zstd frame
if frames:
    print("\n=== Decompressing zstd frames ===")
    try:
        import zstandard as zstd
        dctx = zstd.ZstdDecompressor()
        for i, off in enumerate(frames[:10]):
            try:
                result = dctx.decompress(archive[off:], max_output_size=1024*1024*10)
                print(f"  Frame {i} at 0x{off:x}: {len(result)} bytes")
                if b'\x7fELF' in result[:1024]:
                    print(f"    Contains ELF!")
                    with open(os.path.join(OUTPUT_DIR, f"frame_{i}_0x{off:x}.so"), "wb") as f:
                        f.write(result)
            except Exception as e:
                print(f"  Frame {i} at 0x{off:x}: FAILED ({e})")
    except ImportError:
        pass
