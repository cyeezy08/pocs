# Leviathan

A threat-intel Telegram bot: buttons for the lookups people actually run, an AI
analyst behind them, and **keyless sources underneath** so it scales without
riding one API key.

```
🌐 IP Enrich          🛡 CVE Intel
🏭 Vendor Sweep (KEV) 🔑 Hash Lookup
📡 Exploit Stream     📊 KEV Stats
🤖 Ask the Analyst    ℹ️ Sources & Limits
```

## Why keyless matters

A bot serving many users cannot depend on one academic Shodan key. If that key
is rate-limited, rotated or revoked, the bot dies with it. Everything below is
free and needs no key, so the bot keeps working when a paid key doesn't:

| Source | What it gives | Key |
|---|---|---|
| [Shodan InternetDB](https://internetdb.shodan.io) | IP → ports, CPEs, hostnames, CVEs | **none** |
| [NVD 2.0](https://services.nvd.nist.gov) | CVE detail, CVSS, vector | **none** |
| [EPSS / FIRST.org](https://api.first.org/data/v1/epss) | exploitation probability | **none** |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | known-exploited + due dates | **none** |
| [Exploit-DB](https://www.exploit-db.com/rss.xml) | newest public exploits | **none** |
| abuse.ch MalwareBazaar | hash lookup | `ABUSECH_AUTH_KEY` |

The Shodan **search** API is optional and used only for deep search. Without it
the bot is fully functional.

## The headline button: CVE Intel

One tap returns NVD severity, EPSS probability, and whether CISA lists it as
exploited - then makes a **verdict call**, because a CVSS score alone says how
bad something *would* be, not how bad it *is*:

```
CVE-2021-33044
CVSS: 9.8 (CRITICAL)
Published: 2021-09-15

🔴 EXPLOITED IN THE WILD (CISA KEV)
  • CISA KEV, added 2024-08-21
  • Dahua IP Camera Authentication Bypass Vulnerability
  • Federal due date: 2024-09-11
  • EPSS 0.99987 (99.98th pct)
```

## The analyst

The 🤖 button routes to `hermes chat -q` when Hermes is installed, passing the
question with the intel sources as context. **If Hermes is absent the bot still
answers** - it extracts CVE ids and IPs from the question and runs the same
keyless lookups. A missing model must not make the bot useless.

## Running it

```bash
export TELEGRAM_BOT_TOKEN='...'      # from @BotFather
export BOT_ALLOWED_USERS='123,456'   # optional; omit = open to anyone
export ABUSECH_AUTH_KEY='...'        # optional; enables hash lookup
python3 bot.py
```

Stdlib only - no pip installs. Python 3.11+.

## Design notes

- **Raw long-polling over `urllib`**, not a framework. Zero dependencies means
  zero dependency rot for a bot meant to outlive the machine it was written on.
- **Read-only.** Nothing here resolves, connects to or scans a third-party
  host. InternetDB reads Shodan's index; the target is never touched.
- **Every source degrades honestly.** A dead feed returns a clear message
  rather than an exception, so one bad source can't take the bot down.
- **Responses cached** (15 min) because these feeds change slowly and the bot
  is read-mostly.
- **Attribution** is on every result, per Shodan's billing FAQ ("you can
  integrate the API in your products as long as the data is attributed to
  Shodan").

## Verified

Every formatter was run against live sources before commit:

```
[ok] fmt_ip        8.8.8.8 → ports 53,443 · hostnames · CPEs
[ok] fmt_cve       CVE-2021-33044 → CVSS 9.8, 🔴 EXPLOITED IN THE WILD
[ok] fmt_vendor    Dahua → 2 KEV entries with due dates
[ok] fmt_stream    Exploit-DB → live titles
[ok] fmt_kevstats  1,734 entries, catalog 2026.10.04
[ok] fmt_hash      degrades to a clear key-requirement message
```

## Attribution & scope

Leviathan Offsec × . Threat intel is credited to Shodan, NVD,
FIRST.org, CISA and Exploit-DB on every result.

**Authorized research only.** The bot performs passive index lookups. It does
not scan, probe or interact with any host.

MIT.
