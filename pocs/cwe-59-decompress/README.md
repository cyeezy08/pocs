# decompress - Symlink & Hardlink Path Traversal (Arbitrary File Write)

**CWE-59:** Improper Link Resolution Before File Access
**Advisory ref:** GHSA-mp2f-45pm-3cg9 (fix only in the `@xhmikosr/decompress` fork)

Working proof-of-concept for an arbitrary file write in the `decompress` npm
package (4.2.1, latest) via archive symlink and hardlink entries that escape the
output directory.

> PoCs run entirely in `/tmp`, write to throwaway marker files, and clean up
> after themselves. Use them only to verify the flaw on systems you control.

---

## Summary

| Field | Value |
|-------|-------|
| **Package** | `decompress` |
| **Repository** | `kevva/decompress` |
| **Version** | 4.2.1 (latest) |
| **Downloads** | 17.6M weekly |
| **CWE** | CWE-59 - Improper Link Resolution Before File Access |
| **CVSS** | 7.5 HIGH (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) if escalated to RCE |
| **Fix** | `@xhmikosr/decompress` 10.2.1 / 11.1.3 (fork only, original unpatched) |

---

## How It Works

`decompress()` extracts archives and confines writes to an output directory.
The confinement is incomplete in two ways.

### Vulnerability 1: Symlink Escape

In `index.js:112-124`:

```
line 104-109: realDestinationDir check -> runs for hard links (line 113)
line 116-118: symlink created immediately -> NO CHECK
```

A symlink entry pointing outside the output directory (e.g. `escape.txt -> ../../marker.txt`)
is created with no validation. Any later write through that symlink overwrites an
arbitrary file on the host.

### Vulnerability 2: Hardlink Write Bypass

`preventWritingThroughSymlink` uses `fsP.readlink()` to block symlink writes.
A hardlink entry is created with `fsP.link()` and is **not** covered by that
check. A hardlink pointing at a file outside the output directory, followed by a
write to the same path, overwrites the external file.

### Why both matter

- Attacker only needs the victim to extract a crafted archive.
- No authentication, no privileges, no special user interaction.
- No "does not require" list matters once a malicious zip is extracted.

---

## Proof of Concept

```bash
npm install decompress@4.2.1
node poc_symlink_bypass.js
node poc_hardlink_bypass.js
```

### Symlink run

```
[+] Symlink created: /tmp/decompress-poc-*/output/escape.txt -> ../marker.txt
[+] Symlink points OUTSIDE output directory!
[+] VULNERABILITY CONFIRMED: Arbitrary file write via symlink
    Before: ORIGINAL_CONTENT
    After:  POC_ARBITRARY_WRITE_...
```

### Hardlink run

```
[+] Target file content before: ORIGINAL_CONTENT
[+] Extraction Completed!
[+] Target file content after: POC_HARDLINK_OVERWRITE_SUCCESS
[+] SUCCESS: Bypass confirmed! File outside output directory was overwritten.
```

---

## Impact

- Arbitrary file overwrite via a crafted zip/tar archive.
- Overwritable targets include: SSH keys, cron jobs, shell profiles, config
  files, application binaries.
- Escalation to RCE is possible depending on context (see `docs/analysis.md`).

---

## Recommended Fix

Port `ensureLinkTargetInsideOutput()` from the `@xhmikosr/decompress` fork.
It validates that both symlink and hardlink targets resolve inside the output
directory before creating the link.

---

## Files

| File | Purpose |
|------|---------|
| `poc_symlink_bypass.js` | Symlink escape -> arbitrary write |
| `poc_hardlink_bypass.js` | Hardlink write bypass of `preventWritingThroughSymlink` |
| `docs/analysis.md` | Root-cause breakdown and RCE escalation vectors |
| `advisory.md` | Ready-to-send vendor advisory |

## Disclosure

Vendor disclosure initiated 2026-07-17 (see `advisory.md`). The original package
remains unpatched at 4.2.1; the fix exists only in the maintained fork.

## License

MIT - provided for defensive security research and education only.
