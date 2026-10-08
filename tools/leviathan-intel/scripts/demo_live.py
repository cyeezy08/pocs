"""Leviathan live pipeline demo - the whole engine in one run, no database.

What it does, end to end, with REAL public data:
  1. FINGERPRINT   --domain YOURDOMAIN   : Shodan passive intel on YOUR domain
                   --vendor --product     : or a named stack, e.g. apache log4j
                     [--version]           (Shodan REST; authorized scope only)
  2. CVE MATCH     pulls the newest `--window` CVEs from cvedb.shodan.io and
                   correlates them against the fingerprints (same CPE logic
                   as production, engine.correlate).
  3. ENRICH        each matched CVE gets the rich CVEDB record: EPSS, KEV,
                   plain-language remediation.
  4. PoC SIGNAL    Sploitus is queried per matched CVE: public PoC = +5.
  5. SCORE         engine.scoring.priority_score -> explainable 0-100 priority.

    export SHODAN_API_KEY=...                      # only for --domain mode
    python scripts/demo_live.py --domain leviathan.ac
    python scripts/demo_live.py --vendor apache --product http_server --version 2.4.49

Scope: this tool correlates PASSIVE intel for assets you own/control. It does
not scan, probe, or exploit anything - see README scope policy.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from collections import OrderedDict

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.correlate import asset_matches_cve  # noqa: E402
from engine.scoring import priority_score, triage_label  # noqa: E402

CVEDB = "https://cvedb.shodan.io"
SPLOITUS = "https://sploitus.com/search"
TIMEOUT = 120


def log(stage: str, msg: str) -> None:
    print(f"[{stage}] {msg}", flush=True)


def shodan_get(path: str, **params) -> dict:
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        raise SystemExit("set SHODAN_API_KEY in environment for --domain mode")
    params["key"] = key
    resp = requests.get(f"https://api.shodan.io{path}", params=params,
                        timeout=60)
    resp.raise_for_status()
    return resp.json()


def fingerprints_from_domain(domain: str) -> list[dict]:
    """Passive Shodan fingerprint of a domain the caller is authorized on."""
    resolved = shodan_get("/dns/resolve", hostnames=domain)
    ips = [v for v in resolved.values() if isinstance(v, str)]
    log("1:fp", f"{domain} -> {', '.join(ips) if ips else 'no A records'}")

    fps: "OrderedDict[str, dict]" = OrderedDict()
    for ip in ips[:3]:
        try:
            host = shodan_get(f"/shodan/host/{ip}")
        except Exception as exc:  # noqa: BLE001
            log("1:fp", f"host({ip}) unavailable: {exc}")
            continue
        log("1:fp", f"{ip}: org={host.get('org')} ports={host.get('ports')}")
        for svc in host.get("data", []):
            product = (svc.get("product") or "").strip()
            version = (svc.get("version") or "").strip()
            candidates = []
            if product:
                candidates.append((product.lower().replace(" ", "_"),
                                   product.lower().replace(" ", "_"), version))
            for cpe22 in svc.get("cpe") or []:
                # shodan legacy form: cpe:/a:vendor:product[:version]
                parts = cpe22.strip().split(":")
                if len(parts) >= 5 and parts[0] == "cpe":
                    candidates.append((parts[3].lower(), parts[4].lower(),
                                       parts[5] if len(parts) > 5 else ""))
            for vendor, prod, ver in candidates:
                key = f"{vendor}:{prod}:{ver or '*'}"
                fps.setdefault(key, {
                    "vendor": vendor, "product": prod, "version": ver or "*",
                    "origin": f"{domain} via {ip}",
                    "cpe23": f"cpe:2.3:a:{vendor}:{prod}:{ver or '*'}"
                             f":*:*:*:*:*:*:*",
                })
    return list(fps.values())


def fingerprint_from_args(vendor: str, product: str, version: str) -> list[dict]:
    version = version or "*"
    return [{
        "vendor": vendor.strip().lower().replace(" ", "_"),
        "product": product.strip().lower().replace(" ", "_"),
        "version": version,
        "origin": "operator-supplied stack",
        "cpe23": (f"cpe:2.3:a:{vendor.strip().lower().replace(' ', '_')}:"
                  f"{product.strip().lower().replace(' ', '_')}:{version}"
                  f":*:*:*:*:*:*:*"),
    }]


def pull_window(limit: int) -> list[dict]:
    resp = requests.get(f"{CVEDB}/cves", params={"limit": limit},
                        timeout=TIMEOUT)
    resp.raise_for_status()
    payload = resp.json()
    rows = payload if isinstance(payload, list) else payload.get("cves", [])
    log("2:cve", f"pulled {len(rows)} newest CVEs from cvedb.shodan.io")
    return rows


def synthesize_cpe(row: dict) -> str | None:
    vendor = (row.get("vendor") or "").strip().lower().replace(" ", "_")
    product = (row.get("product") or "").strip().lower().replace(" ", "_")
    if not vendor or not product:
        return None
    version = (row.get("version") or "").strip() or "*"
    return (f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*")


def enrich(cve_id: str) -> dict | None:
    resp = requests.get(f"{CVEDB}/cve/{cve_id}", timeout=60)
    if resp.status_code != 200:
        return None
    return resp.json()


def sploitus_poc(cve_id: str, limit: int = 5) -> tuple[bool, str]:
    try:
        resp = requests.post(
            SPLOITUS,
            json={"query": cve_id, "offset": 0, "sort": "date"},
            headers={"Content-Type": "application/json",
                     "User-Agent": "leviathan-intel-demo/0.2"},
            timeout=30,
        )
        resp.raise_for_status()
        for exploit in resp.json().get("exploits", [])[:limit]:
            tagged = {c.upper() for c in (exploit.get("cve_list") or [])}
            if cve_id.upper() in tagged:
                return True, (exploit.get("href")
                              or f"https://sploitus.com/exploit?id={exploit.get('id')}")
    except Exception as exc:  # noqa: BLE001 - PoC signal is best-effort
        log("4:poc", f"sploitus lookup failed for {cve_id}: {exc}")
    return False, ""


def replay(args: argparse.Namespace) -> None:
    """Score one named CVE against an (optional) operator-declared stack."""
    cve_id = args.cve.upper()
    log("3:enrich", f"{cve_id}: fetching rich record (epss/kev/remediation)")
    rich = enrich(cve_id)
    if not rich:
        print(f"{cve_id}: not found in CVEDB")
        return

    if args.vendor and args.product:
        stack = (f"{args.vendor.strip().lower().replace(' ', '_')}:"
                 f"{args.product.strip().lower().replace(' ', '_')}:"
                 f"{args.version or '*'}")
        reason = f"operator-declared stack: {stack}"
    else:
        stack = "unspecified"
        reason = "single-CVE replay (no stack filter)"

    log("4:poc", f"{cve_id}: checking Sploitus for public PoC")
    has_poc, poc_url = sploitus_poc(cve_id)

    cvss = rich.get("cvss_v3") or rich.get("cvss")
    try:
        cvss = round(float(cvss), 1) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None
    epss = rich.get("epss")
    kev = bool(rich.get("kev"))
    ransom = bool(rich.get("ransomware_campaign"))

    score, reasons = priority_score(cvss=cvss, epss=epss, kev=kev,
                                    public_poc=has_poc)
    label = triage_label(score)

    print("\n" + "=" * 78)
    print(f"{'PRI':>4}  {'LABEL':<9} {'CVE':<20} {'CVSS':>4} {'EPSS':>7} "
          f"{'KEV':<3} PoC  RANSOM  STACK")
    print("-" * 78)
    epss_s = f"{epss:.4f}" if epss is not None else "-"
    print(f"{score:>4}  {label:<9} {cve_id:<20} "
          f"{f'{cvss:.1f}' if cvss is not None else '-':>4} {epss_s:>7} "
          f"{'YES' if kev else '-':<3} {'YES' if has_poc else '-':<4} "
          f"{'YES' if ransom else '-':<6} {stack}")
    print("=" * 78)

    print(f"\nWHY {cve_id} scores {score}/100 ({label}):")
    for why in reasons:
        print(f"  - {why}")
    print(f"  match basis: {reason}")
    if ransom:
        print("  note: CVEDB flags active ransomware campaigns for this CVE")
    if poc_url:
        print(f"  public PoC: {poc_url}")
    fix = (rich.get("propose_action") or "").strip()
    if fix:
        print(f"  suggested fix: {fix[:300]}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--domain", help="YOUR domain (authorized scope only)")
    ap.add_argument("--cve", metavar="CVE-ID",
                    help="replay one CVE through enrich+PoC+score")
    ap.add_argument("--vendor", help="stack vendor, e.g. apache")
    ap.add_argument("--product", help="stack product, e.g. http_server")
    ap.add_argument("--version", default="", help="exact version, if known")
    ap.add_argument("--window", type=int, default=3000,
                    help="how many newest CVEs to scan (default 3000)")
    ap.add_argument("--max-cve-hits", type=int, default=8,
                    help="cap on enrich+PoC lookups (politeness, default 8)")
    args = ap.parse_args()

    print("=" * 78)
    print("LEVIATHAN INTEL - LIVE PIPELINE DEMO (passive, defensive, no scanning)")
    print("=" * 78)

    if args.cve:
        return replay(args)  # --vendor/--product are optional context here

    if bool(args.domain) + bool(args.vendor) != 1:
        ap.error("choose one source: --domain | --vendor(+--product) | --cve")
    if args.domain:
        fps = fingerprints_from_domain(args.domain)
    else:
        if not args.product:
            ap.error("--vendor requires --product")
        fps = fingerprint_from_args(args.vendor, args.product, args.version)

    if not fps:
        print("No fingerprints discovered - nothing to correlate.")
        return
    for fp in fps:
        log("1:fp", f"fingerprint {fp['cpe23']}  ({fp['origin']})")

    window = pull_window(args.window)

    matches = []
    for row in window:
        cve_cpe = synthesize_cpe(row)
        if not cve_cpe:
            continue
        for fp in fps:
            hit, reason = asset_matches_cve(fp["cpe23"], [cve_cpe])
            if hit:
                matches.append({"fp": fp, "row": row, "reason": reason})
                break
    log("2:cve", f"{len(matches)} CVE(s) correlate with the fingerprints")
    if not matches:
        print("\n0 matches. Common causes:\n"
              "  - domain sits fully behind Cloudflare (origin tech invisible)\n"
              "  - stack not present in the newest window (raise --window)\n"
              "  - conservative matcher: only wildcard/exact version matches")
        return

    findings = []
    for m in matches[: args.max_cve_hits]:
        cve_id = m["row"].get("cve_id")
        log("3:enrich", f"{cve_id}: fetching rich record (epss/kev/remediation)")
        rich = enrich(cve_id) or {}
        epss = rich.get("epss")
        kev = bool(rich.get("kev"))
        remediation = (rich.get("propose_action") or "").strip()[:220]

        log("4:poc", f"{cve_id}: checking Sploitus for public PoC")
        has_poc, poc_url = sploitus_poc(cve_id)
        time.sleep(1.0)

        cvss = rich.get("cvss_v3") or rich.get("cvss") or m["row"].get("cvss")
        try:
            cvss = round(float(cvss), 1) if cvss is not None else None
        except (TypeError, ValueError):
            cvss = None

        score, reasons = priority_score(cvss=cvss, epss=epss, kev=kev,
                                        public_poc=has_poc)
        findings.append({
            "cve": cve_id, "fp": m["fp"], "reason": m["reason"],
            "cvss": cvss, "epss": epss, "kev": kev, "poc": poc_url if has_poc else "",
            "score": score, "label": triage_label(score), "why": reasons,
            "fix": remediation,
        })

    findings.sort(key=lambda f: f["score"], reverse=True)

    print("\n" + "=" * 78)
    print(f"{'PRI':>4}  {'LABEL':<9} {'CVE':<20} {'CVSS':>4} {'EPSS':>7} "
          f"{'KEV':<3} PoC  MATCHED ON")
    print("-" * 78)
    for f in findings:
        cvss_s = f"{f['cvss']:.1f}" if f["cvss"] is not None else "-"
        epss_s = f"{f['epss']:.4f}" if f["epss"] is not None else "-"
        print(f"{f['score']:>4}  {f['label']:<9} {f['cve']:<20} {cvss_s:>4} "
              f"{epss_s:>7} {'YES' if f['kev'] else '-':<3} "
              f"{'YES' if f['poc'] else '-':<4} "
              f"{f['fp']['vendor']}:{f['fp']['product']}:{f['fp']['version']}")
    print("=" * 78)

    top = findings[0]
    print(f"\nTOP FINDING {top['cve']} - why it scores {top['score']}/100 "
          f"({top['label']}):")
    for why in top["why"]:
        print(f"  - {why}")
    print(f"  match basis: {top['reason']}")
    if top["poc"]:
        print(f"  public PoC: {top['poc']}")
    if top["fix"]:
        print(f"  suggested fix: {top['fix']}")


if __name__ == "__main__":
    main()
