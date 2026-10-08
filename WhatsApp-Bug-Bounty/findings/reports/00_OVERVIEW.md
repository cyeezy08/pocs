# WhatsApp v2.26.28.71 - Security Audit Findings
## com.whatsapp | HackerOne Bug Bounty

**APK:** /home/kali/2stage/syfe.apk (132MB, 11 DEX files)
**Analysis Date:** 2026-07-19
**Method:** Static analysis (androguard + baksmali, 90,826 smali files)
**Device:** Raspberry Pi Kali ARM64 + physical Android phone (wireless ADB)

---

## Findings Summary

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | UPI Payment Signature Not Verified | MEDIUM | Confirmed |
| 2 | Exported OTP Receivers - No Permission | MEDIUM | Confirmed |
| 3 | WebView Subdomain Allowlist Bypass | MEDIUM | Confirmed |
| 4 | QuickSends Nonce Replay (server-dependent) | LOW-MEDIUM | Confirmed |
| 5 | Native Library (libs.so) - GIF/WebP/MP4 Parsers | UNKNOWN | Needs Ghidra |
| 6 | Exported Services Without Permission | LOW | Confirmed |

---

## File Structure

```
findings/
├── reports/
│   ├── 00_OVERVIEW.md              ← This file
│   ├── 01_UPI_SIGNATURE_BYPASS.md  ← Most reportable finding
│   ├── 02_OTP_RECEIVER_EXPLOIT.md  ← Proven via dynamic testing
│   ├── 03_WEBVIEW_BYPASS.md        ← Subdomain takeover vector
│   ├── 04_QUICKSENDS_NONCE.md      ← Server-dependent
│   ├── 05_NATIVE_LIBRARIES.md      ← RCE attack surface
│   └── 06_EXPORTED_SERVICES.md     ← Defense-in-depth gaps
├── exploit/
│   ├── otp_exploit_frida.js        ← Frida script (needs rooted device)
│   ├── OtpExploitActivity.java     ← Helper APK source
│   ├── test_otp_adb.sh             ← Quick ADB test
│   ├── SETUP.sh                    ← Full setup script
│   └── README.md                   ← Setup instructions
└── native_analysis/
    ├── arm64-v8a/                  ← Extracted .so files for Ghidra
    │   ├── libs.so (13MB)         ← Main library (GIF/WebP/MP4 parsers)
    │   ├── libsuperpack.so
    │   ├── libunwindstack_binary.so
    │   └── libwamo_graphql_flipper.so
    ├── otpmessage_smali/           ← OTP receiver smali code
    ├── upi_receiver_smali/         ← UPI payment receiver smali
    ├── webview_smali/              ← WebView activity smali
    ├── C7m.smali                   ← UPI parameter parser
    └── C77.smali                   ← UPI validation (no sign check)
```
