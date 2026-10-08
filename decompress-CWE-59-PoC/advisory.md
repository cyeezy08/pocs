# decompress@4.2.1 - Link-Following Arbitrary File Write (CWE-59)

**Status:** Unpatched in original package (fix only in `@xhmikosr/decompress` fork)
**CVSS:** 7.5 HIGH (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-59 - Improper Link Resolution Before File Access

## Summary

`decompress` (17.6M weekly downloads) allows symlink and hardlink entries in
archives to point outside the output directory, enabling arbitrary file write on
the host system.

The `@xhmikosr/decompress` fork fixed this in v10.2.1 / v11.1.3
(GHSA-mp2f-45pm-3cg9), but the original `decompress` package was never patched -
4.2.1 is the latest and remains vulnerable.

## Reproduction

```bash
npm install decompress@4.2.1
node poc_symlink_bypass.js
node poc_hardlink_bypass.js
```

## Root Cause

### Symlink escape (`index.js:112-124`)

The extraction logic handles entry types separately:

```
if (x.type === 'link') {          // hard link
    return fsP.link(x.linkname, dest);
}
if (x.type === 'symlink' && win32) {
    return fsP.link(x.linkname, dest);
}
if (x.type === 'symlink') {
    return fsP.symlink(x.linkname, dest);   // <-- no confinement check
}
```

The `realDestinationDir` check that protects hard links and regular files
(lines 104-109) is never applied to symlinks on POSIX systems. A symlink whose
target resolves outside the output directory is created as-is.

### Hardlink bypass of `preventWritingThroughSymlink`

`preventWritingThroughSymlink` uses `fsP.readlink()` to detect and block writes
through symlinks. Hard links are created via `fsP.link()` and are not covered by
the symlink check at all. A subsequent write to a hardlink path that points
outside the output directory overwrites the external file.

## Impact

- Arbitrary file overwrite via a crafted archive.
- Can overwrite SSH keys, cron jobs, config files, application binaries.
- No authentication or special privileges required; only archive extraction.
- Escalation to RCE depending on context (see `docs/analysis.md`).

## Recommended Fix

Port `ensureLinkTargetInsideOutput()` from the `@xhmikosr/decompress` fork.
Validate that both symlink and hardlink targets resolve inside the output
directory before creating the link.

## Timeline

| Date | Event |
|------|-------|
| 2026-07-17 | Vulnerability discovered and verified |
| 2026-07-17 | Vendor disclosure email sent |
| 2026-08-01 | PoC independently re-verified; public release |
