# Leviathan Intel

**Defensive attack-surface management.** Continuous monitoring of *customer-authorized*
assets: CVE ↔ exposed-asset correlation, CISA KEV + EPSS prioritization, explainable
findings, alerting. Built for security teams that need signal, not CVE noise.

> **Scope policy (non-negotiable, enforced in code review):**
> every asset in the database belongs to a tenant who registered it. This platform
> never scans, probes, or enriches third-party systems. Passive feeds (NVD / KEV /
> EPSS / public PoC indexes) describe *vulnerabilities*, not *targets*.

## Architecture

```
              ┌──────────────── ingest tier (cron / Celery beat) ────────────────┐
              │                                                                   │
  CVEDB ────►│ cvedb_sync.py      bulk CVE stream (20k/call, keyless) + rich     │
  (Shodan)   │                     on-demand enrichment (epss/kev/remediation)   │
   CISA KEV ─►│ kev_sync.py        authoritative KEV flags (hourly, small JSON)   │
   FIRST EPSS►│ epss_sync.py       authoritative EPSS scores (daily CSV)          │
   NVD 2.0 ──►│ nvd_sync.py        OPTIONAL backfill: full history + CPE configs  │
   Shodan ───►│ shodan_assets.py   tenant domains -> hosts -> ports/banners/CPEs │
   Sploitus ─►│ poc_sync.py        public PoC availability per CVE (+5 signal)   │
              └──────────────────────────────┬────────────────────────────────────┘
                                             ▼
                                   PostgreSQL (db/schema.sql)
                                     cves · assets · findings
                                             │
                                             ▼
                        engine/run_correlation.py - CPE matching +
                        explainable priority scoring (CVSS/EPSS/KEV/PoC)
                                             │
                                             ▼
                        FastAPI (api/main.py) ── dashboard / alerts (v0.2)
```

**Why this split:** CVEDB (cvedb.shodan.io) is keyless and serves 20k-row
windows, but its list endpoint ignores filters/pagination and omits EPSS/KEV
detail - verified against the live API. So CVEDB feeds the bulk base table,
CISA's feed stays the authoritative KEV source, FIRST's CSV the authoritative
EPSS source, and CVEDB single-CVE lookups do rich on-demand enrichment.
Sploitus is read-only public PoC metadata (title/link/type - never PoC code).
No NVD API key required on the hot path.

## Priority model (explainable, 0-100)

| Signal | Weight | Why |
|---|---|---|
| CVSS v3.1 base | ≤ 40 | raw severity |
| EPSS probability | ≤ 40 | probability of real-world exploitation in 30 days |
| CISA KEV member | +15 | confirmed exploited in the wild |
| Public PoC exists | +5 | exploitation friction is low |

Every finding stores its own reasons list - the dashboard can always answer
"why is this a 92?".

## Quick start (Docker)

```bash
cp .env.example .env           # set ADMIN_TOKEN (+ keys)
docker compose up -d --build   # postgres + schema + API on :8000
```

Without Docker: `pip install -r requirements.txt`, run `db/schema.sql` on any
PostgreSQL 16, then `uvicorn api.main:app`.

### Deploy on a fresh VPS (Contabo day-0)

SSH in as root, then (repo is private - fetch via the authenticated
Contents API):

```bash
export GITHUB_TOKEN=ghp_xxx    # fine-grained PAT, this repo, Contents:Read
curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.raw" \
  https://api.github.com/repos/cyeezy08/leviathan-intel/contents/scripts/bootstrap_server.sh \
  -o bs.sh && bash bs.sh
```

Idempotent: installs docker + ufw (22/80/443), clones to `/opt/leviathan`,
generates ADMIN_TOKEN, prompts for pay addresses (enter skips), builds and
starts api + postgres + settle-watch, health-checks, prints your token.
After: point DNS A record at the IP, then add TLS.

## Operating the pipeline

```bash
python -m ingest.cvedb_sync --window 20000   # bulk CVE stream (cron: daily)
python -m ingest.kev_sync                    # KEV flags (cron: hourly)
python -m ingest.epss_sync                   # EPSS scores (cron: daily)
python -m ingest.cvedb_sync --cve CVE-2024-3400   # rich single-CVE enrichment
python -m ingest.poc_sync --tenant 2 --store # Sploitus PoC refs for own findings
python -m ingest.shodan_assets --tenant 2   # authorized-asset discovery
python -m engine.run_correlation --tenant 2 # write findings
```

`--tenant` seeds: register the customer's domains first via `POST /assets`
(kind=`domain`); the Shodan worker only ever resolves those.

## Live demo (no database needed)

`scripts/demo_live.py` runs the whole engine against real public feeds in one
shot: fingerprint -> CVEDB correlate -> enrich (EPSS/KEV/remediation) ->
Sploitus PoC -> explainable score.

```bash
export SHODAN_API_KEY=...   # only needed for --domain mode

# your own domain (passive Shodan intel, authorized scope only):
python scripts/demo_live.py --domain leviathan.ac

# a named stack against the newest CVE window:
python scripts/demo_live.py --vendor splunk --product splunk --window 20000

# replay a known-exploited CVE through the full scoring path:
python scripts/demo_live.py --cve CVE-2021-44228 --vendor apache --product log4j
```

## Billing (beta): crypto invoices, you hold the keys

No PSP dependency (Stripe account gone; custodial merchant rails carry the
same freeze/KYC class of risk). The beta flow is a crypto invoice with manual
reconciliation - dead simple, zero third-party API on the money path.
Five rails, one per operator wallet (customer picks on their invoice):
`USDT-TON` (default) · `TON` · `USDT-TRON` · `USDT-SOL` · `BTC`.
Addresses are format-validated at invoice time (per-chain charset/length)
so a typo'd env value can't silently swallow a customer's payment.

```
POST /billing/invoices            {tenant_id, plan, amount_usd, currency}
                               -> pay_to address + amount + memo (LVTI-XXXXXX)
             customer sends to that address; you watch it land in YOUR
             wallet (Telegram Wallet, self-custody - your call), then:
POST /billing/invoices/{id}/paid  {"tx_ref": "optional note"}
                               -> atomically promotes tenants.plan
GET  /billing/invoices?tenant_id=N -> invoice history
```

Setup: set `PAY_ADDRESS_TON` / `PAY_ADDRESS_TRON` / `PAY_ADDRESS_SOL` /
`PAY_ADDRESS_BTC` in `.env` (receive-only public addresses; never put a seed
phrase or private key in env). Invoices expire in 3 days; re-marking paid
returns 409. When B2B customers need real receipts, add a PDF invoice
generator on top of the same table.

### Optional auto-settle: Telegram Wallet Pay

Once Wallet Pay merchant approval (KYB) lands, `WALLET_PAY_TOKEN` switches on
a fully automatic path on top of the same invoices - manual rails stay live
as fallback:

```
POST /billing/invoices/{id}/wallet-pay
     {"customer_tg_id": 123, "timeout_seconds": 3600}
  -> pay_link (👛 Wallet Pay checkout; customer pays TON/BTC/USDT)
POST /webhooks/wallet-pay
  (public endpoint; HMAC-verified via WalletPay-Timestamp + WalletPay-Signature)
  ORDER_PAID   -> invoice paid + tenant plan promoted, zero human touch
  ORDER_FAILED -> invoice cancelled with reason
```

Implementation notes: external_id convention `LVTI-INV-{invoice_id}` links
orders back to invoices; webhook verifies base64(HMAC-SHA256(token,
"{METHOD}.{path}.{timestamp}.{base64(body)}")) with constant-time compare;
unknown future webhook event types are ignored rather than rejected.
Custody trade-off documented: Wallet balances are custodial - the earlier
you can self-custody, the fewer parties can freeze your money.

### Auto-settle WITHOUT KYB: `settle_watch` (default on)

Wallet Pay approval is optional - the compose stack ships `settle-watch`,
which watches your own receive addresses on **public keyless chain APIs**
and promotes invoices itself. No merchant account, no token, no approval:

```
python -m billing.settle_watch --probe    # demo: live chain state, no DB
python -m billing.settle_watch --once     # single scan against the DB
python -m billing.settle_watch --loop 60  # poll forever (compose default)
python -m billing.settle_watch --once --dry-run   # report, never settle
```

| Rail | Mode | Settlement rule |
|---|---|---|
| `USDT-TON` | **auto** | exact USDT amount after invoice creation, or invoice memo (LVTI-XXXXXX comment) - toncenter |
| `USDT-TRON` | **auto** | exact USDT amount after invoice creation - tronscan |
| `TON` | assist | inbound tx candidates listed; operator confirms (price drift) |
| `BTC` | assist | confirmed UTXO candidates listed; operator confirms - blockstream |
| `USDT-SOL` | manual | SPL token-account watch needs derived ATAs - v1 backlog |

Safety rails: a tx only qualifies if it arrived after the invoice was
created (±10 min clock skew); identical-amount duplicates in the window are
flagged `ambiguous` and never auto-settle; settling reuses the same
guarded SQL (`status='waiting' AND expires_at > now()`) as the manual
endpoint, so an invoice already paid/expired can't double-promote a tenant.
Stablecoin rails are exact because the invoice's `amount_usd` IS the USDT
amount - no FX drift. Non-pegged rails (TON-native, BTC) stay assist-mode
for exactly that reason.

### Discord alerts (live in v0.2)

`alerting/discord.py` pushes open critical/high findings to a channel
webhook -- your Discord lights up the moment a tenant asset catches a
KEV'd CVE. Set `DISCORD_WEBHOOK_URL` (Discord > channel settings >
integrations > webhooks); unset simply means alerts are off, never an
error.

```
python -m alerting.discord --test          # one-line wiring check
python -m alerting.discord --tenant 2      # push that tenant's alerts
python -m alerting.discord --dry-run       # print the embed, POST nothing
```

Behavior: one batched embed per pass (worst first, 10-finding cap,
critical red / high orange, KEV | PoC badges in the title line, vendor
remediation as the field body). Only `open` findings at priority >= 60
ping -- triaged/remediated work never re-alerts. send() failures raise
so the pipeline can decide fatality; the CLI prints and continues.

## API (v0.1)

| Route | Purpose |
|---|---|
| `GET /health` | liveness |
| `POST /tenants` | create customer, returns API token |
| `POST /assets` | register authorized domain / IP / service |
| `GET /findings?tenant_id=&min_priority=` | prioritized findings + reasons |
| `GET /stats?tenant_id=` | counts by triage band |
| `POST /billing/invoices` | create crypto invoice (pay_to + memo) |
| `GET /billing/invoices?tenant_id=` | invoice history |
| `POST /billing/invoices/{id}/paid` | confirm payment, promote tenant plan |
| `POST /billing/invoices/{id}/wallet-pay` | create 👛 Wallet Pay checkout link (optional) |
| `POST /webhooks/wallet-pay` | Wallet Pay settlement webhook (HMAC-verified) |

Auth: `Authorization: Bearer <ADMIN_TOKEN>` (per-tenant keys enforced in v0.2).

## Status

- [x] PostgreSQL schema (tenants, assets, cves, poc_refs, findings, scan_jobs)
- [x] CVEDB bulk stream + rich on-demand enrichment (keyless, 20k/window)
- [x] CISA KEV + FIRST EPSS authoritative feed workers
- [x] NVD worker kept as optional backfill (full history + CPE configs)
- [x] Shodan authorized-asset discovery worker
- [x] Explainable scoring engine + CPE correlation (17 unit tests)
- [x] FastAPI delivery tier + CI
- [x] Sploitus PoC feed adapter (read-only public metadata, rate-limited)
- [x] Zero-DB live pipeline demo (scripts/demo_live.py)
- [x] Beta billing: 5-rail crypto invoices + atomic plan promotion (admin-reconciled)
- [x] Optional Wallet Pay auto-settle (HMAC-verified webhook, gated on token)
- [ ] Graph attack paths (NetworkX → Neo4j) (v0.2)
- [ ] AI noise filter + daily brief generator (v0.3)
- [x] Discord alert webhooks (v0.2, shipped early)
- [ ] React dashboard, Slack/email webhooks (v0.3)
- [ ] Per-tenant API key auth (v0.2), PDF receipts + TON Pay Mini App checkout (v0.3)

## Engineering notes

- **Correlation is conservative on purpose.** Exact-version or wildcard CPE
  matches only; NVD version *ranges* require real range parsing and land in
  the enrichment step - a missed range match beats a false "you are vulnerable".
- **NVD API key is optional now.** CVEDB covers the hot path keylessly; only
  a full-history backfill (or CPE-configuration needs) requires `nvd_sync`.
- **Feed reality checks are committed.** The CVEDB adapter documents its
  verified server-side quirks (ignored filters/pagination, thin list rows)
  so nobody re-debugs them from zero. Sploitus likewise: keyless POST
  /search, cve_list-tagged results, permalink fallback via exploit id.
- **PoC signal reads metadata only.** Sploitus gives us title/link/type per
  CVE; we store the reference and the +5 score bump, never PoC payloads.
- **EPSS > CVSS for triage.** Half the internet runs services with CVSS 9+
  CVEs; EPSS + KEV is what tells you which ones are actually being exploited.
- **Shodan usage stays passive.** We read Shodan's index for tenant-registered
  domains; we do not task active scans at third parties. This keeps the EDU
  key compliant with Shodan's API terms.
