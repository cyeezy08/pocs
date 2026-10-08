# Leviathan Core

**Explainable exposure correlation on registered assets - feeds in, proof-of-exposure queue out.**

The layer ProjectDiscovery hasn't built: their tools (`subfinder`, `httpx`, `naabu`, `nuclei`) find
and check things. Leviathan Core sits *after* them and answers the question defenders actually pay
for - **"of everything exploitable in the wild, what applies to MY registered assets, and why?"**
Every finding ships with its evidence chain. No silent zeros, no mystery scores.

> Passive correlation against public feeds only - no active scanning. Inventory is
> authorization-gated: the tool refuses to run on anything you don't own or aren't
> contracted to assess. That gate is the product.

## How it works

```text
CISA KEV ─┐
FIRST EPSS ─┤                     ┌─ CVSS base (NVD, on-demand, cached)
NVD refs  ─┴→ match against YOUR ─┼─ EPSS probability      → explainable score → REPORT.md
             registered assets    └─ KEV + PoC evidence      (0-100, reasons attached)
                ↑
   subfinder/httpx output feeds the inventory (eat-from, not compete-with)
```

Scoring formula (from the audited v1 engine, now contract-enforced by tests):

```text
score = min(100, CVSS≤40 + EPSS≤40 + KEV 15 + PoC 5)
```

Every contributing component records a `Reason` with evidence + source. A failed
NVD fetch yields 0 points *and a reason that says so* - degradation is honest, never silent.

## Quick start

```bash
pip install -e .
leviathan sync --cache cache/                 # KEV catalog + EPSS bulk scores (public feeds)
leviathan score --inventory examples/inventory.example.yaml --cache cache/ --out out/
open out/REPORT.md
```

Coming from ProjectDiscovery tooling? Feed your discovered hosts straight in:

```bash
subfinder -d example.com -silent | httpx -silent | \
  leviathan inventory-from-httpx --domain example.com --out inventory.yaml
# add CPEs/product keywords + keep the attestation, then:
leviathan score --inventory inventory.yaml --cache cache/
```

## Tests

```bash
pip install -e . pytest
pytest -q
```

| File | Covers |
|---|---|
| `tests/test_assets.py` | inventory parsing and the authorization gate |
| `tests/test_match.py` | vendor/product matching, CPE and keyword paths |
| `tests/test_score.py` | the score formula and its contract bounds |
| `tests/test_report.py` | report rendering, including degraded-feed output |

CI runs the suite on every push across the supported Python versions.

---

## The authorization gate

```yaml
attestation: authorized        # verbatim - anything else is refused (exit 2)
owner_contact: sec@example.com
assets:
  - identifier: mail.example.com
    cpe: cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*
```

No attestation, no run. This is what makes it a defenders' tool.

## What v0 is honest about

- **Product-level matching.** v0 matches vendor/product (CPE exact or normalized keyword
  overlap, vendor-agreement enforced). Version-range precision is Phase 3; versions are
  recorded as evidence, never silently trusted.
- **KEV-driven v0.** The catalog of *known-exploited* CVEs is the highest-signal starting
  set. A watchlist mode for arbitrary CVE sets is next.
- **Passive only.** Active validation belongs to the proof engine, ships separately,
  and stays tenant-authorized + audit-trailed. It will never be a public feature of this repo.

## Status (build in public)

| Phase | Milestone | Status |
|---|---|---|
| 0 | v1 shipped and fully audited - this repo's rules come from that audit | archived |
| 1 | Deterministic deploys, secrets rotation | in progress |
| 2 | Passive intel: CVE / NVD / KEV / EPSS ingest with per-feed metrics | **this repo** |
| 3 | Explainable correlation + CPE version-range precision | next |
| 4 | Continuous exposure validation at indie-friendly, public pricing | next |
| 5 | Multi-tenant, API-first, enterprise-ready | next |


## The Leviathan stack

| tool | layer |
|---|---|
| surfacediff | what changed on my surface since last run (snapshot/diff) |
| HostageLVX | which of my subdomains are dangling or claimable |
| leviathan-core | which CVEs actually hit my assets, with reasons |

Recon feeds the surface, takeover scanning tests it, the exposure queue
explains it. One pipeline, four focused tools.

## License

MIT
