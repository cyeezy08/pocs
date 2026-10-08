# WhatsApp Android v2.26.28.71 - Security Audit & Exploit Suite

**Bounty Target:** `com.whatsapp` | **Platform:** Android (ARM64) | **Audit Date:** 2026-07-19  
**Methodology:** Static analysis (androguard + baksmali, 90,826 smali files) + Dynamic testing (ADB, Frida)  
**Environment:** Raspberry Pi 5 (Kali Linux ARM64) + Physical Android device (wireless ADB)

---

## The Story

Six days. 90,826 smali files. One Raspberry Pi 5 and a physical device on wireless ADB. That's what this audit took - and it surfaced 6 issues, 3 of which went to Meta via HackerOne.

The grind: decompiled the 132MB APK, mapped every exported component from the manifest, then went after the interesting stuff - payment handlers, OTP receivers, WebView configs, and the native media parsers hidden inside a 13MB *Meta Superpack archive container* (see below).

The highlight: a UPI payment signature bypass, an exported OTP receiver that any installed app can trigger to intercept one-time codes, and a WebView subdomain-bypass that turns a subdomain takeover into a full URL-allowlist bypass.

You can find bugs in the big apps. It just takes patience and the willingness to stare at 90k smali files.

---

## Findings Summary

## Findings Summary

| # | Finding | Severity | CVSS | Status |
|---|---------|----------|------|--------|
| 1 | [UPI Payment Signature Bypass](findings/reports/01_UPI_SIGNATURE_BYPASS.md) | **MEDIUM** | 5.3 | Confirmed - Submitted to HackerOne |
| 2 | [Exported OTP Receivers](findings/reports/02_OTP_RECEIVER_EXPLOIT.md) | **MEDIUM** | 5.3 | Confirmed - Submitted to HackerOne |
| 3 | [WebView Subdomain Bypass](findings/reports/03_WEBVIEW_BYPASS.md) | **MEDIUM** | 6.1 | Confirmed - Submitted to HackerOne |
| 4 | [QuickSends Nonce Replay](findings/reports/04_QUICKSENDS_NONCE.md) | LOW-MED | 3.7 | Confirmed - Server-dependent |
| 5 | [Native Media Parser RCE Surface](findings/reports/05_NATIVE_LIBRARIES.md) | **UNKNOWN** | N/A | Under Active Audit |
| 6 | [Exported Services](findings/reports/06_EXPORTED_SERVICES.md) | LOW | 3.3 | Confirmed - Informational |

---

## Repository Structure

```
0-Day-WhatsApp-Bounty/
├── README.md                          ← You are here
├── .gitignore
│
├── findings/
│   ├── reports/                       ← Detailed vulnerability reports (01-06)
│   │   ├── 00_OVERVIEW.md
│   │   ├── 01_UPI_SIGNATURE_BYPASS.md
│   │   ├── 02_OTP_RECEIVER_EXPLOIT.md
│   │   ├── 03_WEBVIEW_BYPASS.md
│   │   ├── 04_QUICKSENDS_NONCE.md
│   │   ├── 05_NATIVE_LIBRARIES.md
│   │   ├── 06_EXPORTED_SERVICES.md
│   │   ├── HACKERONE_REPORT_UPI_SIGN_BYPASS.md
│   │   ├── HACKERONE_REPORT_OTP_RECEIVER.md
│   │   └── HACKERONE_REPORT_WEBVIEW_BYPASS.md
│   └── whatsapp_manifest.xml          ← Parsed AndroidManifest.xml
│
├── exploit/                           ← OTP Receiver exploit PoC
│   ├── README.md                      ← Setup & usage guide
│   ├── SETUP.sh                       ├── Full setup script (Frida, ADB, dependencies)
│   ├── otp_exploit_frida.js           ← Frida hook for live OTP interception
│   ├── OtpExploitActivity.java        ← Helper APK source (compile with d8)
│   ├── build.sh                       ← APK compilation script
│   ├── test_otp_adb.sh                ← Quick ADB broadcast test
│   └── AndroidManifest.xml            ← Helper APK manifest
│
├── fuzz/                              ← Media parser fuzzing suite
│   ├── surgical_exploit.py            ← Multi-frame GIF heap overflow (thumbnail-safe)
│   ├── exploit_frame_overflow.py      ← Frame size mismatch exploit
│   ├── real_exploit.py                ← Full exploit chain
│   ├── generate_crash_gif.py          ← Crash test case generator
│   ├── webp_exploit.py                ← WebP VP8L malformed transform generator
│   ├── hook_gif_parser.js             ← Frida hook for libgifimage.so tracking
│   └── test_valid.gif                 ← Valid reference GIF
│
└── analysis/                          ← Research & tooling
    ├── extract_superpack.py           ← Meta Superpack archive extractor
    ├── parse_archive.py               ← Archive stream header parser
    ├── parse_archive2.py              ← Alternative archive parser
    ├── parse_ob_archive.py            ← Openbox container unpacker (zstd/zlib)
    ├── findings/
    │   └── ATTACK_SURFACE.md          ← Attack surface enumeration
    ├── ghidra/                         ← Ghidra analysis artifacts
    │   ├── WhatsAppAnalysis.gpr        ← Ghidra project file
    │   ├── decompress_analysis.json
    │   ├── gif_deep_analysis.json      ← GIF parser function mapping
    │   ├── libs_rce_analysis.json      ← RCE surface analysis
    │   ├── media_parser_report.json    ← Media parser overview
    │   ├── superpack_analysis.json     ← Superpack format reverse engineering
    │   └── scripts/                    ← Ghidra automation scripts
    │       ├── extract_media_parsers.py
    │       ├── analyze_superpack_format.py
    │       ├── disasm_gif_key_funcs.py
    │       ├── hunt_rce_vectors.py
    │       └── analyze_decompress.py
    └── manifest/
        ├── AndroidManifest.xml         ← Full parsed manifest
        └── whatsapp_manifest.xml      └─ Formatted manifest
```

---

## The Superpack Discovery

One key finding during this audit: the 13MB `libs.so` is **not** a monolithic native library. It's a **Meta Superpack archive container** - the actual media parsers are compressed inside it.

**Extraction workflow:**
1. `extract_superpack.py` - Extract raw payload from symbol offsets
2. `parse_archive.py` / `parse_archive2.py` - Decipher stream headers
3. `parse_ob_archive.py` - Reconstruct Openbox container, decompress with zstd/zlib

**Recovered targets:**
- `libgifimage.so` (44 KB) - GIF parser (historical RCE source)
- `libwa_sandboxed_gifimage.so` (84 KB) - Sandboxed GIF parser
- `libstatic-webp.so` (43 KB) - WebP parser
- `libwebpencoder-native.so` (21 KB) - WebP encoder

---

## Methodology

**Static Analysis Pipeline:**
```
WhatsApp.apk (132MB, 11 DEX files)
  → apktool (manifest extraction)
  → jadx (Java decompilation)
  → baksmali (90,826 smali files for bytecode-level audit)
  → Ghidra (native library analysis)
```

**Dynamic Testing:**
- ADB broadcast injection for OTP receivers
- Frida instrumentation for runtime hooking
- Custom APK built to test PendingIntent exploitation

---

## Exploit Highlights

### OTP State Pollution (Finding 2)
Any installed app can send intents to WhatsApp's `OtpRequestedReceiver` without permission checks. WhatsApp generates UUID tokens and stores them in a shared `ConcurrentHashMap` singleton before validating the caller.

### WebView Subdomain Bypass (Finding 3)
The host matcher uses `host.endsWith("." + allowedHost)` instead of exact matching. A subdomain takeover on any `*.whatsapp.com` subdomain bypasses the in-app browser's URL allowlist.

### GIF Heap Overflow (Finding 5 - Active Research)
The `surgical_exploit.py` crafts multi-frame GIFs where frame 1 is valid (survives thumbnail generation) but frame 2 declares 1x1 size with massive LZW data, triggering a heap overflow during full decode on the recipient's device.

---

## Responsible Disclosure

Findings 1-3 have been submitted to Meta via HackerOne. Finding 5 is held pending completion of native analysis and verifiable crash/reproduction evidence.

## Disclaimer

This repository contains security research for responsible disclosure purposes only. All testing was performed on the researcher's own devices. No production systems or user data were accessed.