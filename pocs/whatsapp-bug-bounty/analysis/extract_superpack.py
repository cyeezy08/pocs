#!/usr/bin/env python3
"""
Extract packed .so files from WhatsApp's superpack archive in libs.so.
Superpack format: header + multiple compressed streams (each is a .so file).
"""

import struct
import os
import sys

LIBS_SO = "/home/kali/2stage/analysis/so_files/lib/x86_64/libs.so"
OUTPUT_DIR = "/home/kali/2stage/analysis/extracted_libs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(LIBS_SO, "rb") as f:
    data = f.read()

# Symbol addresses from ELF
ARCHIVE_START = 0xc8a0
ARCHIVE_END = 0xe8be2c
ARCHIVE_SIZE = 0xe7f58c

archive = data[ARCHIVE_START:ARCHIVE_END]
print(f"Archive extracted: {len(archive)} bytes (0x{len(archive):x})")

# Read the archive header
# Superpack header: magic bytes, version, stream count
# Let's inspect the first bytes
print(f"First 64 bytes of archive (hex):")
for i in range(0, min(64, len(archive)), 16):
    hex_str = ' '.join(f'{b:02x}' for b in archive[i:i+16])
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in archive[i:i+16])
    print(f"  {i:08x}: {hex_str}  {ascii_str}")

# Look for the superpack magic
# Common superpack magic: 0x53504b50 ("SPKP") or similar
magic = struct.unpack('<I', archive[0:4])[0]
print(f"\nFirst 4 bytes (LE u32): 0x{magic:08x}")

# Try to find the stream header format
# From libsuperpack strings: "Stream ID: %u, UUID: %u, Size: %zu"
# The archive likely has: [num_streams][stream_headers...][compressed_data...]

# Let's look for patterns - the archive might use zstd or lz4 compression
# Check for zstd magic (0xFD2FB528)
for i in range(0, min(1024, len(archive)), 4):
    val = struct.unpack('<I', archive[i:i+4])[0]
    if val == 0xFD2FB528:
        print(f"Found zstd magic at offset {i:#x}")
    if val == 0x184D2204:
        print(f"Found lz4 magic at offset {i:#x}")

# The superpack format from Facebook's open source:
# Header: magic(4) + version(1) + flags(1) + num_streams(2)
# Then for each stream: id(4) + uuid(4) + compressed_size(4) + decompressed_size(4) + data(...)
# But this is the internal format - the archive may have its own container

# Let me try a different approach - look for the actual library names embedded
# We know these are inside: libgifimage.so, libstatic-webp.so, etc.
# Find offsets of these string references
lib_names = [
    b"libgifimage.so",
    b"libstatic-webp.so",
    b"libwa_sandboxed_gifimage.so",
    b"libwebpencoder-native.so",
    b"libopus_mlow.so",
    b"libnative-filters.so",
    b"libsqlitejni.so",
    b"libprofilo_logger.so",
    b"libprofilo_mmapbuf.so",
]

print("\n=== Library name references in archive ===")
for name in lib_names:
    idx = archive.find(name)
    if idx >= 0:
        # Show surrounding context
        start = max(0, idx - 16)
        end = min(len(archive), idx + len(name) + 32)
        context = archive[start:end]
        print(f"  {name.decode()} @ archive offset 0x{idx:x} (file offset 0x{ARCHIVE_START+idx:x})")
        # Show hex context
        hex_ctx = ' '.join(f'{b:02x}' for b in context)
        print(f"    context: {hex_ctx}")
    else:
        print(f"  {name.decode()} - NOT FOUND in archive")

# Now try to find compressed data sections
# Each stream likely starts with a header followed by compressed data
# Let's scan for potential zstd frames (magic 0x28B52FFD in LE = 0xFD2FB528)
print("\n=== Scanning for zstd frames in archive ===")
zstd_magic = b'\x28\xb5\x2f\xfd'
pos = 0
frames = []
while pos < len(archive) - 4:
    idx = archive.find(zstd_magic, pos)
    if idx < 0:
        break
    frames.append(idx)
    pos = idx + 1
    
if frames:
    print(f"Found {len(frames)} zstd frames")
    for i, off in enumerate(frames[:20]):
        print(f"  Frame {i}: offset 0x{off:x} (file 0x{ARCHIVE_START+off:x})")
else:
    print("No zstd frames found")

# Try lz4 frames (0x04224D18)
lz4_magic = b'\x18\x22\x4d\x04'
pos = 0
lz4_frames = []
while pos < len(archive) - 4:
    idx = archive.find(lz4_magic, pos)
    if idx < 0:
        break
    lz4_frames.append(idx)
    pos = idx + 1

if lz4_frames:
    print(f"Found {len(lz4_frames)} LZ4 frames")
    for i, off in enumerate(lz4_frames[:20]):
        print(f"  Frame {i}: offset 0x{off:x} (file 0x{ARCHIVE_START+off:x})")
else:
    print("No LZ4 frames found")

# Try zlib (0x789C)
print("\n=== Scanning for zlib streams ===")
zlib_patterns = [b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e']
zlib_count = 0
for pattern in zlib_patterns:
    pos = 0
    while pos < len(archive) - 2:
        idx = archive.find(pattern, pos)
        if idx < 0:
            break
        zlib_count += 1
        pos = idx + 1
        
print(f"Found {zlib_count} potential zlib streams")

# Save the archive for further analysis
with open(os.path.join(OUTPUT_DIR, "superpack_archive.bin"), "wb") as f:
    f.write(archive)

print(f"\nArchive saved to {OUTPUT_DIR}/superpack_archive.bin")
