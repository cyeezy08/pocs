#!/usr/bin/env python3
"""
Parse WhatsApp superpack archive using checkpoint-based format.
From libsuperpack strings:
- "Could not open archive: %d/%d/%d" → header has 3 fields
- "Invalid stream %d checkpoint %d, value %zu exceeds uncompressed size %zu"
- "Error reading Superpack archive (checkpoints) from APK"
- "Error reading Superpack archive (stream header) from APK"
"""

import struct
import os
import sys
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

# The archive might be in the .data section
# Let me check what's at the exact start
print(f"\nFirst 256 bytes hex dump:")
for i in range(0, min(256, len(archive)), 16):
    hex_str = ' '.join(f'{b:02x}' for b in archive[i:i+16])
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in archive[i:i+16])
    print(f"  {ARCHIVE_START+i:08x}: {hex_str}  {ascii_str}")

# Try to interpret the header in different ways
print("\n=== Header interpretation attempts ===")

# Attempt 1: [magic:4][version:4][num_streams:4]
h = struct.unpack('<3I', archive[0:12])
print(f"Attempt 1 (magic, ver, nstreams): magic=0x{h[0]:08x} ver={h[1]} nstreams={h[2]}")

# Attempt 2: [num_streams:4][checkpoint_size:4][header_size:4]
print(f"Attempt 2 (nstreams, ckpt_size, hdr_size): {h[0]}, {h[1]}, {h[2]}")

# Attempt 3: varint-encoded header
pos = 0
def read_varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7f) << shift
        pos += 1
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, pos

val, pos = read_varint(archive, 0)
print(f"Attempt 3 (varint): first={val}, second={read_varint(archive, pos)}")

# The archive might use a different structure entirely
# Let me look for the "checkpoint" data
# Checkpoints are likely an array of offsets into the compressed data
# for random access to individual streams

# Let me try to find where the actual compressed data starts
# by looking for known compression patterns

print("\n=== Looking for compression signatures ===")
# zstd frame: 0x28 0xB5 0x2F 0xFD (LE: 0xFD2FB528)
# lz4 frame: 0x04 0x22 0x4D 0x18 (LE: 0x184D2204)
# zlib: 0x78 0x9C or 0x78 0x01 or 0x78 0xDA
# snappy: starts with varint length

for i in range(0, min(4096, len(archive))):
    # Check for zstd
    if archive[i:i+4] == b'\x28\xb5\x2f\xfd':
        print(f"  zstd magic at offset 0x{i:x}")
    # Check for lz4
    if archive[i:i+4] == b'\x04\x22\x4d\x18':
        print(f"  lz4 magic at offset 0x{i:x}")
    # Check for zlib
    if archive[i:i+2] in [b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e']:
        print(f"  zlib magic at offset 0x{i:x}")

# Maybe the archive uses a custom format with a simple header
# Let me try: [num_streams:2][per_stream: [id:2, offset:4, size:4]]
# That would be 2 + N*10 bytes header

print("\n=== Trying simple stream table formats ===")
for hdr_size in [2, 4, 8, 12, 16, 20, 24, 32, 64, 128, 256, 512, 1024]:
    num = struct.unpack('<H', archive[0:2])[0]
    if 1 <= num <= 200:
        print(f"  If first u16 is num_streams={num}: header would be {2 + num*10} bytes (10-byte entries)")
        if 2 + num*10 < 4096:
            # Try to read stream entries
            entries = []
            valid = True
            for j in range(min(num, 10)):
                offset = 2 + j*10
                if offset + 10 > len(archive):
                    valid = False
                    break
                sid, soff, ssz = struct.unpack('<HIH', archive[offset:offset+10])
                entries.append((sid, soff, ssz))
            if valid:
                print(f"    First entries: {entries[:5]}")

# Let me try another approach: look for the stream data directly
# The archive might have a fixed header size, then raw compressed data
# Let me try decompressing from various offsets

print("\n=== Trying decompression from various offsets ===")
import zlib

for offset in [0, 4, 8, 12, 16, 20, 24, 32, 64, 128, 256, 512, 1024, 2048]:
    for wbits in [-15, -8, 15, 31, 47]:
        try:
            result = zlib.decompress(archive[offset:], wbits)
            print(f"  SUCCESS at offset 0x{offset:x} wbits={wbits}: decompressed {len(result)} bytes")
            # Save it
            with open(os.path.join(OUTPUT_DIR, f"decompressed_0x{offset:x}.bin"), "wb") as f:
                f.write(result)
            break
        except:
            pass

# Maybe the data is XOR-encoded or uses a simple cipher
# Let me check if there's a repeating key
print("\n=== XOR analysis ===")
# Check if first 1024 bytes XORed with various keys produce readable text
for key in range(256):
    xored = bytes(b ^ key for b in archive[:32])
    if all(32 <= b < 127 or b == 0 for b in xored):
        print(f"  Key 0x{key:02x}: {xored[:32]}")

# Let me also check if the archive is a zip file
print("\n=== Checking for zip signature ===")
zip_sig = archive.find(b'PK\x03\x04')
if zip_sig >= 0:
    print(f"  ZIP signature at offset 0x{zip_sig:x}")
else:
    print("  No ZIP signature found")

# Check for tar
tar_sig = archive.find(b'ustar')
if tar_sig >= 0:
    print(f"  TAR signature at offset 0x{tar_sig:x}")
else:
    print("  No TAR signature found")

# Check for any readable strings in the archive
print("\n=== Searching for readable strings in archive ===")
import re
strings_found = []
for match in re.finditer(rb'[\x20-\x7e]{8,}', archive):
    s = match.group().decode('ascii', errors='ignore')
    offset = match.start()
    if any(kw in s.lower() for kw in ['lib', 'gif', 'webp', 'mp4', 'superpack', 'archive', 'stream']):
        strings_found.append((offset, s))
        print(f"  0x{offset:x}: {s[:80]}")

print(f"\nTotal relevant strings: {len(strings_found)}")
