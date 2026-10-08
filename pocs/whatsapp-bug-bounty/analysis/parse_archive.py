#!/usr/bin/env python3
"""
Parse WhatsApp superpack archive from libs.so to extract packed .so files.
Based on strings from libsuperpack.so:
- Stream ID: %u, UUID: %u, Size: %zu
- _superpack_archive_start / _superpack_archive_end
- Archive from SO uses Openbox format
"""

import struct
import os
import sys
import zlib

LIBS_SO = "/home/kali/2stage/analysis/so_files/lib/x86_64/libs.so"
OUTPUT_DIR = "/home/kali/2stage/analysis/extracted_libs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(LIBS_SO, "rb") as f:
    data = f.read()

# Symbol addresses
ARCHIVE_START = 0xc8a0
ARCHIVE_END = 0xe8be2c
ARCHIVE_SIZE = 0xe7f58c  # from symbol

archive = data[ARCHIVE_START:ARCHIVE_END]
print(f"Archive: {len(archive)} bytes (0x{len(archive):x})")
print(f"Symbol size: 0x{ARCHIVE_SIZE:x}")

# The archive format from superpack is:
# [header][stream_headers...][compressed_data...]
#
# From the strings, the format seems to be:
# - Archive starts with a header
# - Then stream entries with: id(4) + uuid(4) + size(varint) + compressed_data
#
# Let me try to parse the header

# First, check if there's a simple header
# The first bytes: 56 80 91 04 25 cb 59 6e ...
# Could be: magic(4) + version(1) + flags(1) + num_streams(2)

magic = struct.unpack('<I', archive[0:4])[0]
print(f"\nMagic: 0x{magic:08x}")

# Try different header interpretations
# Maybe it's just compressed data from byte 0
# Or maybe there's a small header

# Let's look for the "checkpoint" structure
# From strings: "Invalid stream %d checkpoint %d, value %zu exceeds uncompressed size %zu"
# This suggests there's a checkpoint table

# Let me try to find the stream count by looking for patterns
# The archive might start with: [num_streams:4][stream_headers...]
# where each stream header is: [id:4][uuid:4][compressed_size:4][uncompressed_size:4]

# Let me scan for potential stream headers
# A stream header might have: small id (0-N), UUID (4 bytes), size (reasonable value)

print("\n=== Scanning for potential stream headers ===")
for i in range(0, min(256, len(archive)), 4):
    vals = struct.unpack('<4I', archive[i:i+16])
    id_val = vals[0]
    uuid_val = vals[1]
    compressed = vals[2]
    uncompressed = vals[3]
    
    # Heuristic: id should be small, sizes should be reasonable
    if id_val < 100 and 0 < compressed < 0x1000000 and 0 < uncompressed < 0x10000000:
        ratio = uncompressed / compressed if compressed > 0 else 0
        if 0.1 < ratio < 100:
            print(f"  Offset 0x{i:x}: id={id_val}, uuid=0x{uuid_val:08x}, comp={compressed} (0x{compressed:x}), uncomp={uncompressed} (0x{uncompressed:x}), ratio={ratio:.2f}")

# Alternative: the archive might use varint encoding for sizes
# Let's try reading it as a continuous stream and look for zstd/lz4/zlib frames

print("\n=== Looking for decompression markers ===")
# From libsuperpack: "decompress_with_format" suggests format byte precedes each stream
# Common format bytes: 0=zstd, 1=lz4, 2=zlib, 3=raw

# Let me try a different approach: use the Openbox archive structure
# Openbox archives typically have:
# [magic:4][version:4][num_entries:4][entries...][data...]
# where each entry has: [name_len:4][name:name_len][offset:4][size:4]

# But our archive is inside a .so, so it might be simpler
# Let me look at the raw structure more carefully

# Check if the archive starts with a count
first_u32 = struct.unpack('<I', archive[0:4])[0]
first_u16 = struct.unpack('<H', archive[0:2])[0]
print(f"First u32: {first_u32} (0x{first_u32:08x})")
print(f"First u16: {first_u16} (0x{first_u16:04x})")

# Let me try to find the archive by looking for known patterns
# The archive might have a simple format:
# [num_streams:2][stream0_header][stream0_data]...[streamN_header][streamN_data]

# Actually, let me look at the arm64 version which might have a simpler layout
ARM64_LIBS = "/home/kali/2stage/analysis/so_files/lib/arm64-v8a/libs.so"
with open(ARM64_LIBS, "rb") as f:
    arm64_data = f.read()

# Get arm64 symbols
import subprocess
result = subprocess.run(['nm', '-D', ARM64_LIBS], capture_output=True, text=True)
for line in result.stdout.split('\n'):
    if 'superpack' in line.lower():
        print(f"ARM64: {line.strip()}")

# Check ARM64 archive
arm64_start = None
arm64_end = None
for line in result.stdout.split('\n'):
    if '_superpack_archive_start' in line:
        arm64_start = int(line.split()[0], 16)
    if '_superpack_archive_end' in line:
        arm64_end = int(line.split()[0], 16)

if arm64_start and arm64_end:
    arm64_archive = arm64_data[arm64_start:arm64_end]
    print(f"\nARM64 archive: {len(arm64_archive)} bytes")
    print(f"First 64 bytes:")
    for i in range(0, min(64, len(arm64_archive)), 16):
        hex_str = ' '.join(f'{b:02x}' for b in arm64_archive[i:i+16])
        print(f"  {i:08x}: {hex_str}")
    
    # Compare first bytes with x86_64
    print(f"\nFirst 16 bytes comparison:")
    print(f"  x86_64: {' '.join(f'{b:02x}' for b in archive[:16])}")
    print(f"  arm64:  {' '.join(f'{b:02x}' for b in arm64_archive[:16])}")

# Let me try yet another approach: look for ELF section containing the archive
# The archive might be in a specific section
print("\n=== ELF sections in libs.so ===")
result = subprocess.run(['readelf', '-S', LIBS_SO], capture_output=True, text=True)
for line in result.stdout.split('\n'):
    if '.data' in line or '.rodata' in line or 'superpack' in line.lower():
        print(f"  {line.strip()}")

# Now let me try to actually decompress
# The archive data might be a single zstd-compressed blob
# Or it might have a custom container

# Let me check if zstd can decompress the raw archive
print("\n=== Trying zstd decompression ===")
try:
    import zstandard as zstd
    dctx = zstd.ZstdDecompressor()
    result = dctx.decompress(archive)
    print(f"Zstd decompressed: {len(result)} bytes")
except Exception as e:
    print(f"Zstd failed: {e}")

# Try zlib
print("\n=== Trying zlib decompression ===")
try:
    result = zlib.decompress(archive)
    print(f"Zlib decompressed: {len(result)} bytes")
except Exception as e:
    print(f"Zlib failed: {e}")

# Try raw deflate
print("\n=== Trying raw deflate from offset 0 ===")
try:
    result = zlib.decompress(archive, -15)
    print(f"Raw deflate decompressed: {len(result)} bytes")
except Exception as e:
    print(f"Raw deflate failed: {e}")
