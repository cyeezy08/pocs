# Security Advisory: Denial of Service in braces via Comma-Separated Brace Expansion

## Summary

The `braces` npm package (version 3.0.3, latest) is vulnerable to denial of service through uncontrolled resource consumption when processing comma-separated brace expansion patterns.

The existing fix for CVE-2024-4068 only limited the maximum input length to 10,000 characters but did not address the combinatorial explosion of output when processing comma-separated brace patterns like `{a,b}`.

## Affected Versions

- braces@3.0.3 (latest at time of reporting) - **incomplete fix for CVE-2024-4068**

## Impact

A malicious input as short as **110 characters** can cause:
- **4,194,304 array items** to be materialized in memory
- **~1.2 GB** memory allocation
- **10-30 seconds** of CPU blocking (hardware dependent)
- Complete denial of service in any application that processes untrusted input through `braces.expand()`

Since `braces` is a dependency of `micromatch`, which is used by widely-deployed tools including webpack, vitest, jest, eslint, and many others, the potential impact is significant.

## Technical Details

### Root Cause

In `lib/expand.js`, the `rangeLimit` check (line 60) only applies when `node.ranges > 0`:

```javascript
if (node.ranges > 0) {
  const args = utils.reduce(node.nodes);
  if (utils.exceedsLimit(...args, options.step, rangeLimit)) {
    throw new RangeError('expanded array length exceeds range limit...');
  }
  // ...
}
```

Comma-separated expansions (e.g., `{a,b}{c,d}`) produce AST nodes where `ranges === 0`, so the limit is never checked. The `append()` function recursively materializes all 2^N combinations into an array.

### Proof of Concept

```javascript
const braces = require('braces');
const start = Date.now();
const input = '{a,b}'.repeat(22); // 110 characters
const result = braces.expand(input);
console.log(`${result.length} items in ${Date.now() - start}ms`);
// Output: 4194304 items in ~10000ms
```

### Test Results

Item counts are deterministic. Timing and memory vary by hardware.

| Input (chars) | Output Items | Time (approx) | Memory (approx) |
|---------------|-------------|---------------|-----------------|
| 50 | 1,024 | ~10ms | ~1MB |
| 75 | 32,768 | ~100ms | ~16MB |
| 90 | 262,144 | ~700ms | ~116MB |
| 100 | 1,048,576 | ~2-4s | ~240-470MB |
| 110 | 4,194,304 | ~10-30s | ~1.2GB+ |

## Recommended Fix

Add a limit on the total number of expanded items, regardless of whether the expansion is from numeric ranges or comma-separated patterns. See `patch.diff` for a complete implementation that passes all existing unit tests.

## Distinction from Other CVEs

- **CVE-2024-4068**: Fixed `micromatch/braces` input length limiting. Did not address combinatorial output explosion.
- **CVE-2026-45149**: Affects `juliangruber/brace-expansion` (a separate package), not `micromatch/braces`.

## Disclosure Timeline

- 2026-07-17: Vulnerability discovered
- 2026-07-21: Public disclosure

## Credit

Discovered by cyeezy08.
