# Finding 5: Native Library Attack Surface (libs.so)
## Severity: UNKNOWN (POTENTIAL CRITICAL) | CVSS: N/A - Requires further analysis | Type: Potential RCE via Media Parsing

### Summary

WhatsApp bundles a monolithic 13MB native library (`libs.so`) containing GIF, WebP, and MP4 parsers. These parsers have historically been the source of RCE vulnerabilities in WhatsApp (e.g., CVE-2019-11932 - GIF double-free). The library is not stripped and was built with NDK r25c.

### Library Details

```
File: lib/arm64-v8a/libs.so
Size: 13,069,384 bytes (13MB)
Arch: ELF 64-bit LSB shared object, ARM aarch64
Build: NDK r25c (9519653)
Stripped: No
```

### Media Parsers Found

| Parser | Evidence | Historical CVEs |
|--------|----------|-----------------|
| GIF | `libgifimage.so`, `libwa_sandboxed_gifimage.so` references | CVE-2019-11932 (double-free RCE) |
| WebP | `libstatic-webp.so`, `libwebpencoder-native.so` references | CVE-2023-4863 (Heap buffer overflow) |
| MP4 | `VMp4` string, `Mp4mA` references | Various parsing bugs |

### Why This Matters

1. **GIF parser** was the source of CVE-2019-11932, a critical RCE in WhatsApp
2. **WebP parser** had CVE-2023-4863, a actively exploited 0-day
3. These parsers handle untrusted input (images received in chat)
4. A single malformed image could trigger RCE without user interaction beyond receiving it

### Next Steps (Requires Ghidra/Radare2)

1. Load `libs.so` into Ghidra on a machine with more resources
2. Find JNI entry points (search for `Java_` prefixed functions or JNI registration)
3. Identify the GIF/WebP/MP4 parser functions
4. Check for:
   - Buffer overflows (unchecked memcpy, malloc size miscalculations)
   - Integer overflows (size calculations before allocation)
   - Use-after-free (double-free in GIF parsing)
   - Format string vulnerabilities
5. Fuzz with malformed GIF/WebP/MP4 files

### Files for Analysis

```
/home/kali/2stage/findings/native_analysis/arm64-v8a/libs.so      (13MB - main target)
/home/kali/2stage/findings/native_analysis/arm64-v8a/libsuperpack.so (216KB)
/home/kali/2stage/findings/native_analysis/arm64-v8a/libunwindstack_binary.so
/home/kali/2stage/findings/native_analysis/arm64-v8a/libwamo_graphql_flipper.so
```

### Ghidra Quick Start

```bash
# On your codespace:
ghidraHeadless /tmp/ghidra_project WhatsAppAnalysis \
  -import /home/kali/2stage/findings/native_analysis/arm64-v8a/libs.so \
  -postScript FindJNIFunctions.java \
  -scriptPath /path/to/scripts
```
