# Verdict: CONFIRMED

## Vulnerability
Uncontrolled Resource Consumption (DoS) via comma-separated brace expansion in braces@3.0.3

## Evidence
- PoC demonstrates 110 chars input -> 4,194,304 items, ~10s CPU, ~1.2GB memory
- CVE-2024-4068 fix only limited input length (MAX_LENGTH=10000), not combinatorial output
- `rangeLimit` in expand.js only guards numeric ranges, not comma-separated patterns
- Vulnerability independently verified on 2026-07-21

## CVSS v3.1
AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H = 7.5 HIGH

## Reproduction
```bash
mkdir braces-test && cd braces-test
npm init -y && npm install braces@3.0.3
node -e "const b=require('braces'); const r=b.expand('{a,b}'.repeat(22)); console.log(r.length, 'items')"
```

## Recommended Channel
GitHub Security Advisory (micromatch/braces repo)

## Researcher
cyeezy08
