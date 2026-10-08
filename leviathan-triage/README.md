# leviathan-triage

**The KEV firehose, triaged against YOUR stack, in your Discord. Zero packets, pure intel.**

Part of the Leviathan stack (https://leviathan.ac). The ASN-scale lane needs scanning
infrastructure this team does not have; this lane needs none. The bot correlates
PUBLIC exploit intelligence against software you *declare* - it never sends a packet
to your assets, so there is nothing to authorize, rate-limit, or burn infra on.

```
CISA KEV ──┐
FIRST EPSS ├─► match vs declared assets ─► explainable score ─► P0..P3 ─► Discord
NVD (opt) ─┘        (product tokens)      CVSS40+EPSS40+KEV15+PoC5
```

## Why this exists

Every security team does the same morning ritual: skim the KEV feed, squint at
EPSS, and ask "is any of this *ours*?" The answer today is a spreadsheet and
vibes. leviathan-triage answers it mechanically:

- **Match** - normalized product/vendor token matching between your declared
  inventory and every CISA KEV entry (vendor agreement enforced, so "chrome"
  never matches "chromium").
- **Score** - the audited Leviathan formula, capped at 100:
  `CVSS ≤ 40 + EPSS ≤ 40 + CISA KEV 15 + public PoC 5`.
- **Band** - P0 exploited-in-the-wild and severe (KEV + ransomware association,
  or KEV + EPSS ≥ 0.50, or KEV + CVSS ≥ 9.0 in deep mode) · P1 confirmed
  exploited in the wild · P2 high exploitability signal · P3 context.
- **Ship it where you already live** - Discord webhook (5-minute setup) or a
  native slash-command bot, plus a plain CLI.

## Honest limitations (read before trusting it)

- **Triage is not a scan.** The bot proves nothing about *your* instances;
  it ranks what the feeds say about the *software* you declared. Verify
  before you patch or report.
- **Product-level matching.** Versions are recorded as evidence, never
  verified. A version-range engine is Phase 2 (needs the NVD CPE corpus).
- **The default queue is KEV-correlated.** KEV is the "exploited in the wild"
  signal; CVEs outside KEV surface via `/triage-cve` (EPSS lookup works for
  any CVE) or `--deep` enrichment.
- **CVSS and PoC need `--deep`.** Partial mode is instant and honest: those
  components contribute 0 points and the reasons say "not assessed".
- **Every number is traceable.** Findings carry per-component reasons with
  feed provenance; the winning KEV source (cisa.gov or mirror) is surfaced,
  never silently swapped.

## Install

Zero dependencies. Python 3.9+.

```
git clone https://github.com/cyeezy08/leviathan-triage
cd leviathan-triage
pip install .          # optional; or run in place:
python -m leviathan_triage.cli --help
```

## The 5-minute path: webhook + cron

1. Declare your stack (starts you with a demo inventory - edit it):

```
leviathan-triage init-assets assets.json
```

2. Create a Discord webhook (Server Settings → Integrations → Webhooks),
   then verify wiring:

```
export LT_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
leviathan-triage test-webhook
```

3. Put it on cron - alerts fire **once** per new KEV-matched finding:

```
0 * * * * LT_ASSETS=/opt/triage/assets.json LT_DISCORD_WEBHOOK=... \
          leviathan-triage daemon --once
```

Exit codes: `0` nothing new · `1` new alert-worthy findings · `2` feed
failure. Your cron stays observable.

## The native path: slash commands

```
export LT_DISCORD_BOT_TOKEN="..."        # discord.com/developers - bot, no privileged intents
leviathan-triage register-commands       # auto-detects app id, installs / commands
leviathan-triage gateway                 # run it (any box, tmux/systemd)
```

Commands: `/triage-cve cve:CVE-2024-3400` · `/triage-product product:Ivanti
Connect Secure` · `/kev-today` · `/queue` · `/help`. Intents are 0 - the bot
never reads normal chat.

## CLI tour

```
leviathan-triage sync                        # refresh KEV + EPSS caches, show sources
leviathan-triage triage                      # full queue, reasons inline, [NEW] marks
leviathan-triage triage --json --deep        # machine output + NVD enrichment (slow, cached)
leviathan-triage ask "palo alto globalprotect"
leviathan-triage cve CVE-2024-3400
leviathan-triage kev-today
leviathan-triage daemon --once --no-post     # dry-run a cron cycle
leviathan-triage cache-clean --hard          # fresh start
```

Assets formats (auto-detected): `.json` (declared inventory, the good one),
`.jsonl` (httpx `-json` output - tech detections become keywords),
`.txt` (`vendor/product` per line).

## The formula (do not change it by vibes)

| component | points | source | default |
|-----------|--------|--------|---------|
| EPSS | ≤ 40 | FIRST EPSS bulk CSV (daily) | always on |
| CISA KEV | 15 | cisa.gov → community mirror chain | always on |
| CVSS | ≤ 40 | NVD v2 API, per-CVE cached forever | `--deep` |
| public PoC | 5 | NVD references (exploit/poc keywords) | `--deep` |

Bands: P0 = KEV ∧ (ransomware ∨ EPSS ≥ 0.50 ∨ CVSS ≥ 9.0) · P1 = KEV ·
P2 = EPSS ≥ 0.25 ∨ score ≥ 50 · P3 = rest. Weights live in
`leviathan_triage/config.py` - single source of truth, test-enforced.

## Leviathan stack

| layer | repo | question it answers |
|-------|------|---------------------|
| surface changes | surfacediff | what changed since last run? |
| dangling DNS | hostage | which of my subs can be taken over? |
| exposure triage | **leviathan-triage** (this) | which exploits are mine, in order? |
| full platform | https://leviathan.ac | all of it, hosted, with the scan engine |

## Run it as a product (v0.2.0)

v0.2.0 turns the bot into a sellable feed: a **free daily digest** channel is the
marketing, a **subscriber-only lane** gets P0/P1 the minute the feeds move, and
Gumroad license keys are the gate - verified live on every `/subscribe`, role
granted automatically, revoked the day a subscription lapses.

```
leviathan-triage digest          # free lane: daily digest + buy CTA (cron daily)
leviathan-triage tweet --dry-run # Huginn: the same digest -> X, once a day
LT_DISCORD_WEBHOOK_PAID=... leviathan-triage daemon --once   # paid lane: P0/P1 realtime (cron hourly)
```

Slash commands gain `/subscribe license:…` and `/subscription` (both private).
Full go-live on a $5 VPS - systemd units, installer, and the 45-minute checklist
including the marketing copy - is in `deploy/GO-LIVE.md`.

## Support / fund the feed

The product IS the funding: the free daily digest is the gift, the $5/mo
realtime P0/P1 lane is how you say thanks (and get woken up at 3am when it
matters, not at 9am when the newsletter fires). Click **Sponsor** on this repo
for ko-fi, or grab the feed directly from the Gumroad link in the Sponsor
panel. If neither exists yet for this mirror, the paid lane is one
`LT_GUMROAD_PERMALINK` away - see `deploy/GO-LIVE.md`.

MIT - cyeezy08, 2026.
