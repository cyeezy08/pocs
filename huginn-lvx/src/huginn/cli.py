"""huginn CLI - fetch | draft | post | mirror | status.

Exit contract (cron-friendly, mirrors leviathan-triage):
  0 = work done (or dry-run ok)   1 = nothing to do   2 = error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import config, content, github_feed, mirror, store, xapi


def cmd_fetch(args: argparse.Namespace) -> int:
    user = os.environ.get(config.ENV_GH_USER, "")
    if not user:
        print("error: set HUG_GH_USER (your github username)", file=sys.stderr)
        return config.EXIT_ERROR
    events = github_feed.fetch_events(user)
    known = {e["event_id"] for e in store.read_jsonl("events.jsonl", args.state_dir)}
    fresh = [e for e in events if e["event_id"] and e["event_id"] not in known]
    if not fresh:
        print("fetch: nothing new")
        return config.EXIT_NOTHING
    store.append_jsonl("events.jsonl", fresh, args.state_dir)
    print(f"fetch: {len(fresh)} new event(s) stored")
    for e in fresh:
        print(f"  - [{e['type']}] {e['repo']} {e['tag']}".rstrip())
    return config.EXIT_OK


def cmd_draft(args: argparse.Namespace) -> int:
    events = store.read_jsonl("events.jsonl", args.state_dir)
    if not events:
        print("draft: no events - run `huginn fetch` first")
        return config.EXIT_NOTHING
    rows = content.draft_from_events(
        events,
        posted=store.posted_ids(args.state_dir),
        drafted=store.drafted_ids(args.state_dir),
    )
    if not rows:
        print("draft: nothing new to draft")
        return config.EXIT_NOTHING
    store.append_jsonl("drafts.jsonl", rows, args.state_dir)
    print(f"draft: {len(rows)} drafted")
    for r in rows:
        print(f"  - [{r['type']}] {r['repo']} -> {content.x_length(r['text'])}w chars")
    return config.EXIT_OK


def cmd_post(args: argparse.Namespace) -> int:
    drafts = store.read_jsonl("drafts.jsonl", args.state_dir)
    posted = store.posted_ids(args.state_dir)
    target = next((d for d in drafts if d["event_id"] not in posted), None)
    if target is None:
        print("post: queue empty - run `huginn draft`")
        return config.EXIT_NOTHING

    # X automation rules: respect the minimum interval between posts
    ledger = store.read_jsonl("posted.jsonl", args.state_dir)
    if ledger:
        last = max(int(r.get("ts", 0)) for r in ledger)
        wait = config.MIN_POST_INTERVAL_SEC - (int(time.time()) - last)
        if wait > 0 and not args.force:
            print(f"post: too soon - {wait}s left until the {config.MIN_POST_INTERVAL_SEC // 60}m interval elapses")
            return config.EXIT_NOTHING

    text = target["text"]
    if args.dry_run or not args.yes:
        print("[DRY RUN] would post (rerun with --yes to send):")
        print("-" * 60)
        print(text)
        print("-" * 60)
        print(f"weighted length: {content.x_length(text)}/{config.MAX_POST_CHARS}")
        return config.EXIT_OK

    result = xapi.post_tweet(text)
    tweet_id = (result.get("data") or {}).get("id", "")
    store.append_one(
        "posted.jsonl",
        {
            "event_id": target["event_id"],
            "repo": target["repo"],
            "tweet_id": tweet_id,
            "text": text,
            "ts": int(time.time()),
        },
        args.state_dir,
    )
    print(f"posted: tweet_id={tweet_id} ({target['repo']})")
    return config.EXIT_OK


def cmd_mirror(args: argparse.Namespace) -> int:
    ledger = store.read_jsonl("posted.jsonl", args.state_dir)
    mirrored = {r.get("event_id") for r in store.read_jsonl("mirrored.jsonl", args.state_dir)}
    fresh = [r for r in ledger if r.get("event_id") not in mirrored]
    if not fresh:
        print("mirror: nothing new")
        return config.EXIT_NOTHING
    for r in fresh[-10:]:
        mirror.send_message(r["text"])
        store.append_one("mirrored.jsonl", {"event_id": r["event_id"], "ts": int(time.time())}, args.state_dir)
        print(f"mirrored: {r['event_id']}")
    return config.EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    events = store.read_jsonl("events.jsonl", args.state_dir)
    drafts = store.read_jsonl("drafts.jsonl", args.state_dir)
    posted = store.read_jsonl("posted.jsonl", args.state_dir)
    print(f"events: {len(events)}  drafts: {len(drafts)}  posted: {len(posted)}")
    if posted:
        last = posted[-1]
        print(f"last post: {last.get('ts')} -> {last.get('repo')}")
    return config.EXIT_OK


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="huginn", description="Huginn LVX - GH->X auto-pilot")
    parser.add_argument("--state-dir", default=None, help="override state dir (default ~/.huginn)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("fetch", help="pull latest public GitHub events")
    p.set_defaults(func=cmd_fetch)
    p = sub.add_parser("draft", help="render queued events into 280-safe drafts")
    p.set_defaults(func=cmd_draft)
    p = sub.add_parser("post", help="post the next draft (dry run unless --yes)")
    p.add_argument("--yes", action="store_true", help="actually send (default: dry run)")
    p.add_argument("--dry-run", action="store_true", help="force dry run even with --yes")
    p.add_argument("--force", action="store_true", help="skip the 15-minute interval guard")
    p.set_defaults(func=cmd_post)
    p = sub.add_parser("mirror", help="mirror posted tweets to Telegram")
    p.set_defaults(func=cmd_mirror)
    p = sub.add_parser("status", help="show queue counts")
    p.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    try:
        sys.exit(args.func(args))
    except (github_feed.FeedError, xapi.XApiError, mirror.MirrorError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(config.EXIT_ERROR)


if __name__ == "__main__":
    main()
