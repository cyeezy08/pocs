"""leviathan-triage CLI - triage | ask | cve | kev-today | daemon | post |
test-webhook | register-commands | gateway | init-assets | sync | cache-clean

Exit codes (cron-friendly):
  0 - success, nothing alert-worthy
  1 - success with NEW alert-worthy findings (KEV-matched)
  2 - operational failure (feeds down, bad config)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import config
from . import assets as assets_mod
from .feeds import Feeds
from .state import State


def _state_dir(args) -> Path:
    d = Path(args.state_dir or os.environ.get(config.ENV_STATE_DIR)
             or config.DEFAULT_STATE_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


class FeedSyncError(Exception):
    """Raised by _daemon_cycle when feeds cannot be synced."""


def _assets_or_exit(args):
    path = args.assets or os.environ.get(config.ENV_ASSETS)
    if not path:
        print("no assets file - pass --assets or set LT_ASSETS "
              "(start with `init-assets`)", file=sys.stderr)
        sys.exit(2)
    try:
        return assets_mod.load(path)
    except assets_mod.AssetError as e:
        print(f"assets error: {e}", file=sys.stderr)
        sys.exit(2)


def _webhook_url(args) -> str:
    url = args.webhook or os.environ.get(config.ENV_WEBHOOK) or ""
    if not url:
        print("no webhook - pass --webhook or set LT_DISCORD_WEBHOOK",
              file=sys.stderr)
        sys.exit(2)
    return url


def _print_finding(f, mark_new: bool = False) -> None:
    mark = "[NEW] " if mark_new else ""
    print(f"  {mark}{f.summary()}")
    for r in f.reasons:
        print(f"    {r.line()}")


# ----------------------------------------------------------------- commands
def cmd_init_assets(args) -> int:
    path = args.path or "assets.json"
    if Path(path).exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite)")
        return 0
    got = assets_mod.write_starter(path)
    print(f"wrote {path} with {len(got)} demo assets - edit it to YOUR stack")
    print("every entry is software you declare; the bot sends nothing to it")
    return 0


def cmd_sync(args) -> int:
    feeds = Feeds(_state_dir(args) / "cache", transport=None)
    t0 = time.time()
    kev = feeds.kev(force=args.force)
    epss = feeds.epss(force=args.force)
    if args.json:
        print(json.dumps({
            "kev": {"count": len(kev), "source": feeds.kev_source()},
            "epss": {"count": len(epss), "model": feeds.epss_model_date()},
            "seconds": round(time.time() - t0, 1),
        }, indent=2))
    else:
        print(f"KEV  {len(kev):>6} entries  ({feeds.kev_source()})")
        print(f"EPSS {len(epss):>6} scored  (model {feeds.epss_model_date()})")
        print(f"synced in {time.time() - t0:.1f}s -> {_state_dir(args) / 'cache'}")
    return 0


def cmd_triage(args) -> int:
    assets = _assets_or_exit(args)
    sdir = _state_dir(args)
    feeds = Feeds(sdir / "cache")
    try:
        kev = feeds.kev()
        epss = feeds.epss()
    except Exception as e:  # noqa: BLE001
        print(f"feed sync failed: {e}", file=sys.stderr)
        return 2

    nvd = None
    if args.deep:
        from .match import match_all
        cves = sorted({cve for cve, *_ in match_all(assets, kev)})
        nvd = feeds.nvd_batch(cves, api_key=os.environ.get("NVD_API_KEY", ""))
        print(f"NVD deep enrichment: {len(nvd)} CVEs", file=sys.stderr)

    from .score import build_queue
    findings = build_queue(assets, kev, epss, nvd=nvd)
    state = State(sdir / "state.json")
    fresh = [f for f in findings if state.is_new(f)]

    if args.json:
        print(json.dumps({
            "findings": [{
                "cve": f.cve, "asset": f.asset.identifier, "band": f.band,
                "score": f.score, "is_new": f in fresh,
                "epss": f.epss, "in_kev": f.in_kev,
                "known_ransomware": f.known_ransomware, "cvss": f.cvss,
                "match": f.match_confidence,
                "reasons": [r.line() for r in f.reasons],
            } for f in findings],
            "counts": _counts(findings), "new": len(fresh),
            "kev_source": feeds.kev_source(), "epss_model": feeds.epss_model_date(),
        }, indent=2))
    else:
        print(f"queue - {len(findings)} findings "
              f"({', '.join(f'{b}x{c}' for b, c in sorted(_counts(findings).items()))})")
        print(f"KEV {feeds.kev_source()} · EPSS model {feeds.epss_model_date()}")
        print()
        for f in findings:
            _print_finding(f, mark_new=(f in fresh))
        if not findings:
            print("nothing matched - either a quiet surface or a thin inventory")
    state.mark(findings)
    return 1 if fresh else 0


def _counts(findings) -> dict:
    out: dict = {}
    for f in findings:
        out[f.band] = out.get(f.band, 0) + 1
    return out


def cmd_ask(args) -> int:
    feeds = Feeds(_state_dir(args) / "cache")
    from .commands import cmd_triage_product
    embed = cmd_triage_product(" ".join(args.product), feeds)
    if args.json:
        print(json.dumps(embed, indent=2))
    else:
        print(embed.get("title", ""))
        for field in embed.get("fields", []):
            print(f"  {field['name']}")
            print(f"    {field['value']}")
    return 0


def cmd_cve(args) -> int:
    feeds = Feeds(_state_dir(args) / "cache")
    from .commands import cmd_triage_cve
    embed = cmd_triage_cve(args.cve_id, feeds)
    if args.json:
        print(json.dumps(embed, indent=2))
    else:
        print(embed.get("title", ""))
        print(embed.get("description", ""))
        for field in embed.get("fields", []):
            print(f"  {field['name']}: {field['value']}")
    return 0


def cmd_kev_today(args) -> int:
    feeds = Feeds(_state_dir(args) / "cache")
    from .commands import cmd_kev_today
    embed = cmd_kev_today(feeds)
    if args.json:
        print(json.dumps(embed, indent=2))
    else:
        print(embed.get("title", ""))
        for field in embed.get("fields", []):
            print(f"  {field['name']}")
            print(f"    {field['value']}")
    return 0


def _daemon_cycle(args, state: State) -> int:
    """One sync->match->alert pass. Returns count of NEW findings."""
    sdir = _state_dir(args)
    feeds = Feeds(sdir / "cache")
    assets = _assets_or_exit(args)
    try:
        kev = feeds.kev()
        epss = feeds.epss()
    except Exception as e:  # noqa: BLE001
        raise FeedSyncError(str(e)) from e  # no print here: caller decides
    from .score import build_queue
    findings = build_queue(assets, kev, epss)
    fresh = [f for f in findings if state.is_new(f)]
    paid_url = os.environ.get(config.ENV_WEBHOOK_PAID, "")
    hot = [f for f in fresh if f.band in config.SUBSCRIBER_BANDS]
    if fresh:
        from .discord import finding_embed, summary_embed, post_webhook

        def chunk(head, body):
            if len(body) <= config.WEBHOOK_EMBED_LIMIT - 1:
                return [[head] + body]
            messages = [[head] + body[: config.WEBHOOK_EMBED_LIMIT - 1]]
            rest = body[config.WEBHOOK_EMBED_LIMIT - 1:]
            for i in range(0, len(rest), config.WEBHOOK_EMBED_LIMIT):
                messages.append(rest[i:i + config.WEBHOOK_EMBED_LIMIT])
            return messages

        if paid_url:
            # two-lane mode: P0/P1 -> subscriber webhook in realtime.
            # P2/P3 surface only in the free daily digest (`digest` on cron).
            messages = chunk(summary_embed(hot, new_only=True),
                             [finding_embed(f, mark_new=True) for f in hot]) if hot else []
            if args.json:
                print(json.dumps({"new": len(fresh), "hot": len(hot),
                                  "paid_lane": True, "posted": len(messages)}))
            else:
                print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {len(fresh)} NEW "
                      f"({len(hot)} P0/P1 -> paid lane, "
                      f"{len(messages)} message(s))")
                for f in fresh:
                    _print_finding(f, mark_new=True)
            if not args.no_post and messages:
                for embeds in messages:
                    post_webhook(paid_url, embeds)
        else:
            # single-lane mode (default trial setup): everything -> one webhook
            messages = chunk(summary_embed(fresh, new_only=True),
                             [finding_embed(f, mark_new=True) for f in fresh])
            if args.json:
                print(json.dumps({"new": len(fresh), "hot": len(hot),
                                  "paid_lane": False, "posted": len(messages)}))
            else:
                print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {len(fresh)} NEW "
                      f"findings -> webhook ({len(messages)} message(s))")
                for f in fresh:
                    _print_finding(f, mark_new=True)
            if not args.no_post:
                url = _webhook_url(args)
                for embeds in messages:
                    post_webhook(url, embeds)
    else:
        if args.json:
            print(json.dumps({"new": 0, "hot": 0,
                              "paid_lane": bool(paid_url), "posted": 0}))
        elif not args.daemon:
            print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - nothing new "
                  f"({len(findings)} known findings, state kept)")
    state.mark(findings)
    return len(fresh)


def cmd_daemon(args) -> int:
    state = State(_state_dir(args) / "state.json")
    if args.once:
        try:
            fresh = _daemon_cycle(args, state)
        except FeedSyncError as e:
            print(f"feed sync failed: {e}", file=sys.stderr)
            return 2  # cron mode: distinct code so infra can alert
        return 1 if fresh else 0
    print(f"daemon started - interval {args.interval}s, Ctrl-C to stop")
    while True:
        try:
            _daemon_cycle(args, state)
        except FeedSyncError as e:
            print(f"feed sync failed (continuing): {e}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 - a bot that dies is a bot that lies
            print(f"cycle error (continuing): {e}", file=sys.stderr)
        time.sleep(args.interval)


def cmd_digest(args) -> int:
    """The FREE daily digest -> free webhook, with the buy CTA. Cron this."""
    assets = _assets_or_exit(args)
    sdir = _state_dir(args)
    feeds = Feeds(sdir / "cache")
    try:
        kev = feeds.kev()
        epss = feeds.epss()
    except Exception as e:  # noqa: BLE001
        print(f"feed sync failed: {e}", file=sys.stderr)
        return 2
    from .score import build_queue
    from .discord import digest_embed, post_webhook
    findings = build_queue(assets, kev, epss)
    embed = digest_embed(findings, buy_url=os.environ.get(config.ENV_BUY_URL, ""),
                         limit=args.limit)
    if args.no_post:
        print(json.dumps(embed, indent=2))
        return 0
    post_webhook(_webhook_url(args), [embed])
    print(f"digest posted - {len(findings)} findings")
    return 0


def cmd_post(args) -> int:
    assets = _assets_or_exit(args)
    sdir = _state_dir(args)
    feeds = Feeds(sdir / "cache")
    try:
        kev = feeds.kev()
        epss = feeds.epss()
    except Exception as e:  # noqa: BLE001
        print(f"feed sync failed: {e}", file=sys.stderr)
        return 2
    from .score import build_queue
    from .discord import queue_embeds, post_webhook
    findings = build_queue(assets, kev, epss)
    top = findings[: args.limit]
    post_webhook(_webhook_url(args), queue_embeds(top))
    print(f"posted {len(top)} of {len(findings)} findings to webhook")
    return 0


def cmd_test_webhook(args) -> int:
    from .discord import post_webhook
    embed = {
        "title": "leviathan-triage wired",
        "description": (f"{config.POSITIONING}\n\n{config.DISCLAIMER}"),
        "color": config.BAND_COLORS["P1"],
        "footer": {"text": f"v{config.VERSION} · triage | daemon | ask | queue"},
    }
    post_webhook(_webhook_url(args), [embed])
    print("webhook OK - embed posted")
    return 0


def cmd_register_commands(args) -> int:
    from .gateway import get_application_id, register_commands
    token = args.token or os.environ.get(config.ENV_BOT_TOKEN) or ""
    if not token:
        print("no bot token - pass --token or set LT_DISCORD_BOT_TOKEN",
              file=sys.stderr)
        return 2
    app_id = args.app_id or os.environ.get(config.ENV_APP_ID) or ""
    if not app_id:
        app_id = get_application_id(token)
        print(f"application id detected: {app_id}")
    got = register_commands(token, app_id)
    print(f"registered {len(got)} slash commands: "
          + ", ".join("/" + c["name"] for c in got))
    return 0


def cmd_gateway(args) -> int:
    from .gateway import GatewayClient, respond_interaction
    from .commands import respond_to_interaction
    from .paywall import Paywall
    token = args.token or os.environ.get(config.ENV_BOT_TOKEN) or ""
    if not token:
        print("no bot token - pass --token or set LT_DISCORD_BOT_TOKEN",
              file=sys.stderr)
        return 2
    sdir = _state_dir(args)
    feeds = Feeds(sdir / "cache")
    assets = None
    path = args.assets or os.environ.get(config.ENV_ASSETS)
    if path:
        try:
            assets = assets_mod.load(path)
        except assets_mod.AssetError as e:
            print(f"assets error (queue command disabled): {e}", file=sys.stderr)
    paywall = Paywall.from_env(store_path=sdir / "subscribers.json")
    if paywall is None:
        print("paywall: OFF (no LT_GUMROAD_PERMALINK) - free digest mode")
    else:
        print(f"paywall: ON (gumroad/{paywall.permalink}, "
              f"{len(paywall.store.subs)} active subscriber record(s))")

    def on_interaction(d):
        data = respond_to_interaction(d, feeds, assets, paywall)
        respond_interaction(d["id"], d["token"], data)
        name = (d.get("data") or {}).get("name", "?")
        print(f"interaction: /{name} from {d.get('member', {}).get('user', {}).get('username', 'user')}")

    print("gateway bot running - Ctrl-C to stop")
    GatewayClient(token, intents=0, on_interaction=on_interaction,
                  log=lambda s: print(s, flush=True)).run()
    return 0


def cmd_tweet(args) -> int:
    """Huginn: compose + post the daily P0 digest to X. Cron/timer once a day.

    Exit codes: 0 posted (or dry-run) · 1 nothing worth posting ·
    2 config error · 3 X API error (rate limit, auth, tier).
    """
    from . import xposter
    from .score import build_queue
    if args.verify:
        try:
            me = xposter.verify_credentials()
        except xposter.XApiError as e:
            print(f"verify failed: {e}", file=sys.stderr)
            return 3
        print(f"verified: @{me.get('username', '?')} (id {me.get('id', '?')})")
        return 0
    assets = _assets_or_exit(args)
    sdir = _state_dir(args)
    feeds = Feeds(sdir / "cache")
    try:
        kev = feeds.kev()
        epss = feeds.epss()
    except Exception as e:  # noqa: BLE001
        print(f"feed sync failed: {e}", file=sys.stderr)
        return 2
    findings = build_queue(assets, kev, epss)
    link = args.link if args.link is not None else os.environ.get(config.ENV_X_LINK, "")
    text = xposter.compose_post(findings, link=link)
    if text is None:
        print("nothing P0/P1 in the queue - Huginn stays on the perch")
        return 1
    if args.dry_run:
        print(f"--- would post ({len(text)} chars) ---")
        print(text)
        print("--- end ---")
        return 0
    try:
        res = xposter.post_tweet(text)
    except xposter.XApiError as e:
        print(f"post failed: {e}", file=sys.stderr)
        return 3
    print(f"posted https://x.com/i/status/{res['id']}")
    return 0


def cmd_cache_clean(args) -> int:
    sdir = _state_dir(args)
    cache = sdir / "cache"
    n = 0
    if cache.exists():
        for p in sorted(cache.rglob("*")):
            if p.is_file():
                p.unlink()
                n += 1
    st = sdir / "state.json"
    if args.hard and st.exists():
        st.unlink()
        n += 1
    print(f"removed {n} file(s) under {sdir}" + (" (state reset)" if args.hard else ""))
    return 0


# ------------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    # shared flags accepted BOTH globally and after the subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state-dir", default=argparse.SUPPRESS,
                        help="cache+state root (default ~/.leviathan-triage)")
    common.add_argument("--assets", default=argparse.SUPPRESS,
                        help="assets file (json/jsonl/txt)")
    common.add_argument("--webhook", default=argparse.SUPPRESS,
                        help="Discord webhook URL")
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="machine output")

    p = argparse.ArgumentParser(
        prog="leviathan-triage",
        description=config.POSITIONING + " Triage is not a scan: zero packets.")
    p.add_argument("--state-dir", default=None)
    p.add_argument("--assets", default=None)
    p.add_argument("--webhook", default=None)
    p.add_argument("--json", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("init-assets", parents=[common],
                       help="write a starter assets.json")
    s.add_argument("path", nargs="?", default="assets.json")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init_assets)

    s = sub.add_parser("sync", parents=[common], help="refresh KEV + EPSS caches")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_sync)

    s = sub.add_parser("triage", parents=[common], help="full queue vs your assets")
    s.add_argument("--deep", action="store_true",
                   help="NVD per-CVE enrichment (CVSS + PoC), slow without key")
    s.set_defaults(fn=cmd_triage)

    s = sub.add_parser("ask", parents=[common], help="triage a product string vs KEV")
    s.add_argument("product", nargs="+")
    s.set_defaults(fn=cmd_ask)

    s = sub.add_parser("cve", parents=[common], help="triage one CVE")
    s.add_argument("cve_id")
    s.set_defaults(fn=cmd_cve)

    s = sub.add_parser("kev-today", parents=[common], help="newest KEV additions")
    s.set_defaults(fn=cmd_kev_today)

    s = sub.add_parser("daemon", parents=[common], help="alert on NEW KEV-matched findings")
    s.add_argument("--interval", type=int, default=3600)
    s.add_argument("--once", action="store_true",
                   help="one cycle then exit (cron mode)")
    s.add_argument("--no-post", action="store_true", help="print, do not post")
    s.set_defaults(fn=cmd_daemon, daemon=False)

    s = sub.add_parser("post", parents=[common], help="post current queue top-N to webhook")
    s.add_argument("--limit", type=int, default=config.MAX_QUEUE_PREVIEW)
    s.set_defaults(fn=cmd_post)

    s = sub.add_parser("digest", parents=[common],
                       help="post the FREE daily digest with the buy CTA")
    s.add_argument("--limit", type=int, default=5,
                   help="max P0/P1 lines in the digest body")
    s.add_argument("--no-post", action="store_true", help="print, do not post")
    s.set_defaults(fn=cmd_digest)

    s = sub.add_parser("test-webhook", parents=[common],
                       help="send one embed, verify wiring")
    s.set_defaults(fn=cmd_test_webhook)

    s = sub.add_parser("register-commands", parents=[common],
                       help="install slash commands")
    s.add_argument("--token", default=None)
    s.add_argument("--app-id", default=None)
    s.set_defaults(fn=cmd_register_commands)

    s = sub.add_parser("gateway", parents=[common], help="run the slash-command bot")
    s.add_argument("--token", default=None)
    s.set_defaults(fn=cmd_gateway)

    s = sub.add_parser("tweet", parents=[common],
                       help="Huginn: post the P0 digest to X (free-tier safe)")
    s.add_argument("--dry-run", action="store_true", help="print the post, do not send")
    s.add_argument("--verify", action="store_true",
                   help="check credentials via /2/users/me and exit")
    s.add_argument("--link", default=None,
                   help="link appended to the post (default: LT_X_LINK)")
    s.set_defaults(fn=cmd_tweet)

    s = sub.add_parser("cache-clean", parents=[common], help="clear cached feeds")
    s.add_argument("--hard", action="store_true", help="also reset seen-state")
    s.set_defaults(fn=cmd_cache_clean)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not getattr(args, "fn", None):
        build_parser().print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
