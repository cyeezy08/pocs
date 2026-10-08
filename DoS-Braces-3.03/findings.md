# Findings: braces 3.0.3

## Finding 1: Uncontrolled Resource Consumption via Comma-Separated Brace Expansion

**Severity: HIGH (CVSS 7.5)**

### Description
The `braces.expand()` function materializes all combinations of comma-separated brace expansions into an array. The CVE-2024-4068 fix only limited input length (`MAX_LENGTH=10000`) but did NOT limit the combinatorial output. The `rangeLimit` check in `expand.js:60` only applies to numeric ranges (`{1..1000}`), not to comma-separated patterns (`{a,b}`).

### Root Cause
- File: `lib/expand.js:57-71`
- The `rangeLimit` guard only fires when `node.ranges > 0`
- Comma-separated expansions (`{a,b}{c,d}`) have `node.ranges === 0`
- No equivalent limit exists for combinatorial expansion

### Impact
- Input: `{a,b}` repeated 20 times = **100 characters** (well under 10,000 limit)
- Output: **1,048,576 items** (2^20)
- Time: **~2-4 seconds** CPU block (hardware dependent)
- Memory: ~240MB+ heap allocation
- At 30 repetitions (150 chars): **1 billion items** -> OOM/crash

### Attack Vector
Any application that passes user-controlled input to `braces.expand()` or `braces()` is vulnerable. Since `braces` is a dependency of `micromatch` (used by webpack, vitest, jest, eslint, etc.), this affects a huge portion of the Node.js ecosystem.

### Distinction from Other CVEs
- **CVE-2024-4068**: Fixed input length limiting for `micromatch/braces`. Did not address combinatorial output.
- **CVE-2026-45149**: Affects `juliangruber/brace-expansion` (a different npm package entirely), not `micromatch/braces`.

### Reproduction
```javascript
const braces = require('braces');
const input = '{a,b}'.repeat(20); // 100 chars
braces.expand(input); // hangs for ~2-4s, produces 1M items
```

### Fix Recommendation
Add a limit on the total output size of `expand()`, not just input length. The `rangeLimit` should apply to ALL expansions, not just numeric ranges. See `patch.diff` for a proposed implementation.
