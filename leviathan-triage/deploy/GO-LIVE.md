# GO-LIVE - bare VPS to first subscriber in ~45 minutes

Product: **Leviathan P0 Feed** - the KEV firehose triaged against a declared
stack. Free daily digest is the marketing; realtime P0/P1 alerts are the
product ($5/mo, Gumroad). No packets, no scanning, no infra risk - pure
public-intel correlation. This runbook assumes Ubuntu 22.04/24.04.

The math: Gumroad fee ~10% → **$4.30/mo per subscriber**. One subscriber =
profit. Ten = $43/mo for a box that costs $5.

---

## 0. Ship the code to the VPS (2 min)

From your machine:

```
rsync -av --exclude '*.pyc' --exclude '__pycache__' --exclude 'tests' \
      leviathan-triage/ root@YOUR_VPS:/root/leviathan-triage/
ssh root@YOUR_VPS
bash /root/leviathan-triage/deploy/install.sh
```

Installer creates `/opt/leviathan-feed`, venv, `leviathan` system user, both
timers. Nothing runs yet - the `.env` is empty.

## 1. Discord side (12 min)

1. **App**: https://discord.com/developers → New Application → *Leviathan Feed*.
   Bot tab → Reset Token → copy into `/opt/leviathan-feed/.env`
   (`LT_DISCORD_BOT_TOKEN`). No privileged intents - the bot never reads chat.
2. **Invite** (OAuth2 → URL Generator): scopes `bot` + `applications.commands`,
   perms `Manage Roles` + `Send Messages` + `Embed Links`. Open the URL, add to
   your feed server.
3. **Channels**:
   - `#p0-digest` - PUBLIC. The free daily digest lives here. Everyone sees it.
   - `#p0-alerts` - PRIVATE. View access only for the subscriber role.
4. **Role**: Server Settings → Roles → create `Feed Subscriber` - its ONLY
   permission is viewing `#p0-alerts`. Drag it BELOW the bot's role.
5. **Webhooks**: In `#p0-digest` → Integrations → Webhooks → copy URL →
   `LT_DISCORD_WEBHOOK`. Same for `#p0-alerts` → `LT_DISCORD_WEBHOOK_PAID`.
6. **IDs**: User Settings → Advanced → Developer Mode ON. Right-click your
   server → Copy ID → `LT_DISCORD_GUILD_ID`. Right-click `Feed Subscriber`
   role → Copy ID → `LT_DISCORD_ROLE_ID`.

## 2. Inventory (3 min)

Edit `/opt/leviathan-feed/assets.json` - replace the demo with a REAL, common
stack so the public digest shows interesting findings (this is the demo
content that sells): Ivanti Connect Secure, Palo Alto PAN-OS, Fortinet
FortiGate, Cisco ASA, Microsoft Exchange, VMware vSphere, Chrome, Windows 11.

Then:

```
cd /opt/leviathan-feed
venv/bin/leviathan-triage register-commands      # installs /subscribe etc.
venv/bin/leviathan-triage test-webhook           # -> #p0-digest gets one embed
systemctl restart leviathan-feed-gateway
systemctl start leviathan-feed-digest.service    # first digest posts NOW
```

Discord check: `/kev-today` and `/triage-product product:Palo Alto` answer in
`#p0-digest`. The digest embed shows counts + top P0/P1 + the buy CTA (empty
link says "ask the admin" until step 3 - that's fine).

## 3. Gumroad (8 min)

1. gumroad.com → Products → New → **Leviathan P0 Feed - realtime P0/P1 CVE
   alerts in Discord**, type: **Subscription, $5/month**.
2. Product URL becomes `gumroad.com/l/XXXX` → permalink `XXXX` →
   `LT_GUMROAD_PERMALINK` in `.env`; full URL → `LT_BUY_URL`.
3. Gumroad dashboard → Settings → License keys: ensure the product issues
   license keys (subscriptions do by default).
4. `systemctl restart leviathan-feed-gateway` (paywall turns ON at boot - the
   log line says `paywall: ON`).

Smoke test the gate: buy your own product once (you get the $5 back at the end
of the month, or run a 100%-off test code and delete it after). In Discord:
`/subscribe license:<key>` → private "feed active" reply → role appears →
`#p0-alerts` becomes visible. `/subscription` shows the record. Cancel from
Gumroad → `/subscription` → access revoked. That is the whole lifecycle.

## 3.5 Huginn - the X auto-poster (8 min)

The raven carries the digest to X once a day, one post, always linking back
to the free Discord channel. Free-tier API is write-only - which is exactly
enough for a poster and exactly useless for engagement farming, so the bot
does neither more nor less.

0. **⚠ Your Huggin v1 keys were pasted into a Discord channel. Consider them
   public.** Before go-live: developer.x.com → Huggin v1 → Keys and tokens →
   **Regenerate** Consumer Key/Secret. Then paste the NEW pair into
   `/opt/leviathan-feed/.env` only - never into chat, never into code.
1. Keys and tokens tab → **OAuth 1.0a Access Token + Secret → Generate**
   (that is YOUR account's posting credential; one click, no OAuth dance).
2. App permissions → **Read and Write** (default Read is not enough to post).
3. `.env`: `LT_X_CONSUMER_KEY/SECRET`, `LT_X_ACCESS_TOKEN/SECRET`,
   `LT_X_LINK=<your Discord invite>`. Then:
   ```
   venv/bin/leviathan-triage tweet --verify    # -> verified: @you
   venv/bin/leviathan-triage tweet --dry-run   # prints the post, sends nothing
   systemctl enable --now leviathan-feed-tweet.timer   # daily 13:05 UTC
   ```
4. Post shape (auto-composed, always ≤280 chars, URL counted as t.co's 23):
   ```
   KEV watch: 3 exploited-in-the-wild CVE(s) matched common stacks (P0x1, P1x2)
   P0 CVE-2026-XXXX 95/100 - PAN-OS auth bypass +ransomware
   triage yours free: <your Discord invite>
   ```
   Quiet day → no post (`exit 1`), the raven stays on the perch. Rate-limited
   → the error names the reset epoch instead of dying silently.

Cadence is 1/day by design: free tier allows far more, but a feed that
posts once daily at the same hour trains followers; a feed that spams gets
the app flagged and the funnel killed.

## 4. First revenue moves (15 min)

The digest channel IS the ad. Every post ends with the CTA. Now point traffic
at it:

**X/Twitter** (manual, not a bot - no API, no ban risk):

> CISA added N exploited-in-the-wild CVEs this week. Nobody reads the raw feed.
> We triage it against the stack everyone actually runs (Ivanti, PAN-OS,
> FortiGate, Exchange) and rank what deserves your morning panic - free daily
> digest in Discord: LINK

**Reddit**: r/cybersecurity, r/blueteamsec, r/AskNetsec - post the free
digest as content ("This week's KEV, triaged - [pastebin/Discord link]"), the
paid lane never gets pushed directly; the free value does the selling.

**Communities**: 3-5 bug-bounty / sysadmin Discord servers you're actually in
- share the free digest channel, not the sales pitch.

**Show HN** (when you want volume): "Show HN: I built a P0 alert feed that
watches CISA KEV so you don't have to" - the zero-packets/no-scan story is
the differentiator; lead with honesty (the bot's own /help text is already
disclaimer-perfect).

Cadence that works: free digest daily at 09:00 ET (timer already set), P0/P1
realtime in the paid lane, one X post whenever KEV adds a juicy CVE -
`venv/bin/leviathan-triage kev-today` tells you when.

## 5. Operations one-pager

```
systemctl status leviathan-feed-gateway          # bot alive
journalctl -u leviathan-feed-gateway -f          # slash command log
journalctl -u leviathan-feed-alerts.service      # hourly alert runs (exit 1 = posted)
journalctl -u leviathan-feed-digest.service      # daily digest runs
/opt/leviathan-feed/state/subscribers.json       # who pays you (git-ignore this)
```

- `daemon` exit 0 = quiet, 1 = posted, 2 = feeds down (systemd retries; CISA
  outages are common, the mirror chain handles most of them).
- New subscriber but no role: check bot role rank vs `Feed Subscriber`, then
  `journalctl -u leviathan-feed-gateway | grep subscribe`.
- Updating the bot: re-run `install.sh` (it never touches `.env` or state).
- Backups: `state/` is the only thing that matters; it is 2 small JSON files.

## Pricing later, shipping now

$5/mo is deliberate: impulse-buy territory, no trial infrastructure needed
(the free digest IS the trial). When you cross ~25 subs, raise to $9 for new
subscribers and add a $49/yr tier - Gumroad handles both, the gate does not
change. Do not build a panel, a website, or an email flow before subscriber
#10. Revenue first, polish later.
