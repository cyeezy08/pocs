# huginn-lvx

**Huginn LVX** - GitHub-to-X.com auto-pilot for the Leviathan X stack. Odin's *thought* raven (Munin remembers your surface, Huginn speaks about your code).

Watches your public GitHub activity (releases, new repos, pushes, repos going public), renders each event into a 280-weighted-char post, and publishes to X on your schedule - **dry-run by default, your content, your account, ToS-clean** (no reply-farming, no follow tricks, min 15-minute interval enforced between posts).

## Pipeline

```text
huginn fetch   ->  events.jsonl   (github events API, HTML profile fallback)
huginn draft   ->  drafts.jsonl   (templated, deduped vs posted ledger, capped 5/run)
huginn post    ->  X API v2       (DRY RUN unless --yes; --force skips interval guard)
huginn mirror  ->  Telegram       (backup feed of everything posted)
huginn status  ->  counts
```

Exit codes: `0` work done · `1` nothing to do · `2` error - cron-friendly.

## Quick start

```bash
uv sync
export HUG_GH_USER=cyeezy08
uv run huginn fetch
uv run huginn draft
uv run huginn post          # dry run - inspect, then:
uv run huginn post --yes    # actually posts (needs X keys in env)
```

VPS (systemd, Ubuntu 22.04/24.04 · Debian 12):

```bash
sudo bash deploy/install.sh          # /opt/huginn, huginn user, 2x/day timer, .env never overwritten
sudo nano /opt/huginn/.env           # HUG_GH_USER first - fetch/draft need ZERO X keys
sudo systemctl start huginn-pilot    # runs fetch -> draft -> post
journalctl -u huginn-pilot -n 30     # dry-run preview of the exact next tweet
```

The pilot runs `fetch -> draft -> post`. The post step stays a **dry run** until you set `HUG_AUTOPILOT=1` in `.env` - the OS-level version of "dry-run by default". Timer: 09:20 + 21:20 UTC (max 2 posts/day), with the 15-minute interval guard underneath it.

Plain cron works too (`fetch`, `draft`, `post` - exit codes are cron-friendly), the systemd kit is just the batteries-included path.

## Environment

| Variable | Purpose |
|---|---|
| `HUG_GH_USER` | GitHub username to watch (required for fetch) |
| `HUG_X_API_KEY` / `HUG_X_API_SECRET` | X developer app consumer keys |
| `HUG_X_ACCESS_TOKEN` / `HUG_X_ACCESS_SECRET` | your account's access tokens |
| `HUG_TG_TOKEN` / `HUG_TG_CHAT` | optional Telegram mirror |
| `HUG_STATE_DIR` | state dir (default `~/.huginn`) |
| `HUG_EVENTS_URL` | override events API URL (tests/mirrors) |

X free tier is enough: ~500 posts/month, no read access needed.

## Design notes

- **Zero dependencies** - stdlib only (OAuth 1.0a HMAC-SHA1 signing hand-rolled and validated against Twitter's documented test vector: `hCtSmYh+iHYCEqBWrE7C7hYmtUk=`).
- **X weighted length** - URLs count fixed 23, CJK/emoji count 2; posts are clamped to the real 280 limit, not naive char count.
- **Rate-limit resilient** - when the GitHub API 4xxs (shared IPs burn 60/hr fast), it falls back to scraping your public profile page and synthesizes "repo updated" events with stable dedupable ids.
- **Atomic state** - jsonl append with tmp+rename; a crashed run leaves a skippable partial line, never poisoned state.
- **Dry-run default** - `post` prints the exact tweet and its weighted length unless `--yes` is passed.

## Status (0.1.2)

41 tests, green offline in ~0.1s, no network required for the suite. Live-verified against a real account feed (28 events fetched, drafts rendered, dry-run clean). 0.1.2 adds `.github/FUNDING.yml` + a Support section; 0.1.1 added the `deploy/` kit: idempotent installer, `huginn-pilot.service` + 2x/day timer, `HUG_AUTOPILOT` dry-run switch, env template with the key-rotation warning baked in.

Authorized-self automation only: the bot posts **your** content to **your** account. Don't point it at someone else's tokens.

## Support

Huginn is free and will stay free - it exists to sell its sibling, the
[Leviathan P0 Feed](https://github.com/cyeezy08) ($5/mo realtime KEV lane). If
Huginn made your release notes fly, the repo's **Sponsor** button (ko-fi /
Gumroad, set in `.github/FUNDING.yml`) is the tip jar.
