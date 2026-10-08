#!/usr/bin/env python3
"""
bot.py - Leviathan threat-intel bot.

Buttons for the things people actually look up, an AI analyst behind them, and
keyless sources underneath so it scales without riding one API key.

Design decisions worth knowing
------------------------------
* stdlib only. Raw Telegram long-polling over urllib rather than a framework,
  so the same file runs on the VPS, on Replit, or anywhere with Python 3.11+.
  Zero pip installs means zero dependency rot, which matters for a bot meant
  to outlive the machine it was written on.
* Keyless by default. InternetDB, NVD, EPSS, CISA KEV and Exploit-DB need no
  key. Shodan's academic key is used ONLY for the deep search button, and the
  bot still works without it.
* The AI analyst shells out to `hermes chat -q` when Hermes is installed, and
  degrades to a structured summary when it is not. A missing model should
  never make the bot useless.
* Read-only. Nothing here connects to, resolves, or scans a third-party host.
  InternetDB queries Shodan's index, not the target.

Run:
    export TELEGRAM_BOT_TOKEN=...
    python3 bot.py
"""
from __future__ import annotations

import html
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import sources as S

TG = "https://api.telegram.org/bot{token}/{method}"
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
POLL_TIMEOUT = 50

# Who may use it. Empty = open. Set to a comma-separated list of numeric ids
# to keep a public bot from being a free service for strangers.
ALLOWED = {x.strip() for x in os.environ.get("BOT_ALLOWED_USERS", "").split(",") if x.strip()}

# Per-user pending input, so a button tap can ask a follow-up question.
PENDING: dict[int, str] = {}

MENU = {
    "inline_keyboard": [
        [{"text": "🌐 IP Enrich", "callback_data": "act:ip"},
         {"text": "🛡 CVE Intel", "callback_data": "act:cve"}],
        [{"text": "🏭 Vendor Sweep (KEV)", "callback_data": "act:vendor"},
         {"text": "🔑 Hash Lookup", "callback_data": "act:hash"}],
        [{"text": "📡 Exploit Stream", "callback_data": "act:stream"},
         {"text": "📊 KEV Stats", "callback_data": "act:kevstats"}],
        [{"text": "🤖 Ask the Analyst", "callback_data": "act:ai"}],
        [{"text": "ℹ️ Sources & Limits", "callback_data": "act:about"}],
    ]
}

PROMPTS = {
    "ip": ("Send an IP address to enrich.\n\n"
           "<i>Queries Shodan's InternetDB index. The host is never contacted.</i>"),
    "cve": ("Send a CVE id (e.g. <code>CVE-2021-33044</code>).\n\n"
            "<i>Pulls NVD severity, EPSS exploitation probability, and whether "
            "CISA lists it as exploited in the wild.</i>"),
    "vendor": ("Send a vendor or product name (e.g. <code>Dahua</code>).\n\n"
               "<i>Lists every CISA KEV entry for it - the 'is this actually "
               "being exploited' question, answered at vendor scale.</i>"),
    "hash": ("Send an md5 / sha1 / sha256 digest.\n\n"
             "<i>Needs <code>ABUSECH_AUTH_KEY</code> set; abuse.ch moved to "
             "authenticated lookups.</i>"),
    "ai": ("Ask the analyst anything about a CVE, an IP, a vendor, or a "
           "finding. It has the intel sources above as tools.\n\n"
           "<i>Example: 'is CVE-2021-33044 worth prioritising for a camera "
           "fleet?'</i>"),
}


# ---------------------------------------------------------------------------
# Telegram transport
# ---------------------------------------------------------------------------
def api(method: str, **params) -> dict:
    url = TG.format(token=TOKEN, method=method)
    data = urllib.parse.urlencode(
        {k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
         for k, v in params.items()}).encode()
    req = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req, timeout=POLL_TIMEOUT + 15) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        print(f"[tg] {method} HTTP {e.code}: {body}", file=sys.stderr)
        return {"ok": False, "error": body}
    except Exception as e:  # noqa: BLE001
        print(f"[tg] {method} failed: {type(e).__name__}: {e}", file=sys.stderr)
        return {"ok": False}


def send(chat_id: int, text: str, keyboard: dict | None = None) -> None:
    api("sendMessage", chat_id=chat_id, text=text[:4096],
        parse_mode="HTML", disable_web_page_preview=True,
        reply_markup=keyboard if keyboard is not None else MENU)


def answer_cb(cb_id: str, text: str = "") -> None:
    api("answerCallbackQuery", callback_query_id=cb_id, text=text[:200])


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------
def esc(x) -> str:
    return html.escape(str(x if x is not None else "-"))


def fmt_ip(ip: str) -> str:
    d = S.internetdb(ip)
    if "error" in d:
        return f"❌ {esc(d['error'])}"
    if not d.get("found"):
        return (f"<b>{esc(ip)}</b>\n\nNo record in Shodan's index.\n"
                f"<i>That means unobserved, not necessarily clean.</i>")
    lines = [f"<b>{esc(d.get('ip'))}</b>"]
    if d.get("hostnames"):
        lines.append(f"<b>Hostnames</b>: {esc(', '.join(d['hostnames'][:6]))}")
    if d.get("ports"):
        lines.append(f"<b>Open ports</b>: {esc(', '.join(str(p) for p in d['ports']))}")
    if d.get("cpes"):
        lines.append("<b>CPEs</b>:\n" + "\n".join(
            f"  <code>{esc(c)}</code>" for c in d["cpes"][:8]))
    if d.get("tags"):
        lines.append(f"<b>Tags</b>: {esc(', '.join(d['tags']))}")
    if d.get("vulns"):
        lines.append("<b>Known CVEs</b>: " + esc(", ".join(d["vulns"][:10])))
    else:
        lines.append("<b>Known CVEs</b>: none indexed")
    lines.append("\n<i>Source: Shodan InternetDB. Host not contacted.</i>")
    return "\n".join(lines)


def fmt_cve(cve: str) -> str:
    d = S.cve_intel(cve)
    if "error" in d:
        return f"❌ {esc(d['error'])}"
    if not d.get("found"):
        return f"<b>{esc(cve)}</b>\n\nNot found in NVD."
    lines = [f"<b>{esc(d['id'])}</b>"]
    if d.get("cvss") is not None:
        lines.append(f"<b>CVSS</b>: {esc(d['cvss'])} ({esc(d.get('severity'))})")
    lines.append(f"<b>Published</b>: {esc(d.get('published'))}")
    v = d.get("verdict", "")
    mark = "🔴" if "EXPLOITED" in v else ("🟠" if "high" in v else "🟢")
    lines.append(f"\n{mark} <b>{esc(v)}</b>")
    if d.get("kev"):
        k = d["kev"]
        lines.append(f"  • CISA KEV, added {esc(k.get('dateAdded'))}")
        lines.append(f"  • {esc(k.get('vulnerabilityName'))}")
        lines.append(f"  • Federal due date: {esc(k.get('dueDate'))}")
    if d.get("epss"):
        e = d["epss"]
        lines.append(f"  • EPSS {e['epss']:.5f} ({e['percentile']*100:.2f}th pct)")
    desc = d.get("description", "")
    if desc:
        lines.append(f"\n<i>{esc(desc[:600])}</i>")
    lines.append("\n<i>Sources: NVD · EPSS (FIRST.org) · CISA KEV</i>")
    return "\n".join(lines)


def fmt_vendor(name: str) -> str:
    d = S.kev_vendor(name)
    if "error" in d:
        return f"❌ {esc(d['error'])}"
    if not d.get("count"):
        return (f"<b>{esc(name)}</b>\n\nNo CISA KEV entries.\n"
                f"<i>Nothing known-exploited, which is not the same as nothing "
                f"vulnerable.</i>")
    lines = [f"<b>{esc(name)}</b> - {d['count']} KEV entr"
             f"{'y' if d['count'] == 1 else 'ies'}\n"]
    for e in d["entries"][:15]:
        lines.append(f"<b>{esc(e['cveID'])}</b> · added {esc(e['dateAdded'])}")
        lines.append(f"  {esc(e['product'])} - {esc(e['vulnerabilityName'])}")
    if d["count"] > 15:
        lines.append(f"\n<i>…and {d['count'] - 15} more.</i>")
    lines.append("\n<i>Source: CISA KEV</i>")
    return "\n".join(lines)


def fmt_stream(limit: int = 12) -> str:
    d = S.exploitdb_latest(limit)
    if "error" in d:
        return f"❌ {esc(d['error'])}"
    lines = ["<b>📡 Exploit-DB - latest</b>\n"]
    for it in d.get("items", []):
        lines.append(f"• {esc(it['title'][:95])}")
    lines.append("\n<i>Source: Exploit-DB RSS</i>")
    return "\n".join(lines)


def fmt_hash(h: str) -> str:
    d = S.hash_lookup(h)
    if "error" in d:
        extra = f"\n\n<i>{esc(d.get('note',''))}</i>" if d.get("note") else ""
        return f"❌ {esc(d['error'])}{extra}"
    if d.get("query_status") != "ok":
        return f"<b>{esc(h[:32])}…</b>\n\nNo record.\n<i>Source: abuse.ch</i>"
    data = (d.get("data") or [{}])[0]
    lines = [f"<b>{esc(h[:32])}…</b>"]
    for k in ("file_name", "file_type_mime", "signature", "first_seen",
              "reporter", "tags"):
        if data.get(k):
            lines.append(f"<b>{esc(k)}</b>: {esc(data[k])}")
    lines.append("\n<i>Source: abuse.ch MalwareBazaar</i>")
    return "\n".join(lines)


def fmt_kevstats() -> str:
    d = S.kev()
    if "error" in d:
        return f"❌ {esc(d['error'])}"
    return (f"<b>CISA KEV catalog</b>\n\n"
            f"Entries: <b>{esc(d.get('count'))}</b>\n"
            f"Version: {esc(d.get('catalogVersion'))}\n\n"
            f"<i>Every CVE here has been exploited in the wild and has a "
            f"binding federal remediation deadline.</i>")


def fmt_about() -> str:
    return (
        "<b>Leviathan</b>\n"
        "Threat intel, keyless where possible.\n\n"
        "<b>Sources</b>\n"
        "• Shodan InternetDB - IP enrichment, no key\n"
        "• NVD 2.0 - CVE detail, no key\n"
        "• EPSS (FIRST.org) - exploitation probability, no key\n"
        "• CISA KEV - known-exploited catalog, no key\n"
        "• Exploit-DB - public exploit stream, no key\n"
        "• abuse.ch - hash lookup, needs <code>ABUSECH_AUTH_KEY</code>\n\n"
        "<b>Why keyless</b>\n"
        "A bot that scales to many users cannot ride one API key. These "
        "sources are free and stable, so the bot works even when a paid key "
        "is rate-limited, rotated or revoked.\n\n"
        "<b>Read-only</b>\n"
        "Nothing here resolves, connects to or scans a third-party host. "
        "InternetDB reads Shodan's index; the host is never touched.\n\n"
        "<b>Attribution</b>\n"
        "Shodan data is attributed as required. Exploit-DB, NVD, FIRST and "
        "CISA are credited on every result.\n\n"
        "<i>For authorized research only.</i>"
    )


# ---------------------------------------------------------------------------
# The AI analyst - Hermes if present, structured fallback if not.
# ---------------------------------------------------------------------------
def hermes_available() -> bool:
    return bool(shutil.which("hermes")) or os.path.exists(
        os.path.expanduser("~/.local/bin/hermes"))


def ask_analyst(question: str) -> str:
    """Route the question to Hermes with the intel sources as context.

    If Hermes is unavailable the bot still answers, using the same keyless
    sources directly. A missing model must not make the bot useless.
    """
    exe = shutil.which("hermes") or os.path.expanduser("~/.local/bin/hermes")
    if exe and os.path.exists(exe):
        prompt = (
            "You are the analyst behind a threat-intel Telegram bot. Answer "
            "concisely for a phone screen, in plain text (no markdown tables). "
            "Be explicit about what is confirmed versus inferred, and say "
            "'unknown' rather than guessing.\n\n"
            f"Question: {question}"
        )
        try:
            r = subprocess.run([exe, "chat", "-q", prompt],
                               capture_output=True, text=True, timeout=150)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()[:3500]
        except Exception:  # noqa: BLE001
            pass

    # Fallback: do the obvious lookups the question implies.
    q = question.strip()
    out = ["<i>(analyst model unavailable - answering from the keyless sources)</i>\n"]
    import re as _re
    cves = _re.findall(r"CVE-\d{4}-\d{4,}", q, _re.I)
    if cves:
        for c in cves[:3]:
            out.append(fmt_cve(c.upper()))
            out.append("")
    ips = _re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", q)
    if ips:
        for ip in ips[:3]:
            out.append(fmt_ip(ip))
            out.append("")
    if not cves and not ips:
        out.append("I can look up CVE ids, IP addresses and vendors. Try:\n"
                   "  • <code>is CVE-2021-33044 being exploited?</code>\n"
                   "  • <code>Dahua</code>\n"
                   "  • <code>8.8.8.8</code>")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
def handle_action(chat_id: int, action: str, cb_id: str | None = None) -> None:
    if cb_id:
        answer_cb(cb_id)
    if action in PROMPTS:
        PENDING[chat_id] = action
        send(chat_id, PROMPTS[action], keyboard={"inline_keyboard":
             [[{"text": "⬅️ Menu", "callback_data": "act:menu"}]]})
        return
    if action == "stream":
        send(chat_id, fmt_stream())
        return
    if action == "kevstats":
        send(chat_id, fmt_kevstats())
        return
    if action == "about":
        send(chat_id, fmt_about())
        return
    if action == "menu":
        PENDING.pop(chat_id, None)
        send(chat_id, "<b>Leviathan</b>\nPick a lookup:", MENU)
        return
    send(chat_id, "Unknown action.", MENU)


def handle_text(chat_id: int, text: str) -> None:
    action = PENDING.pop(chat_id, None)
    if action == "ip":
        send(chat_id, fmt_ip(text.strip()))
    elif action == "cve":
        send(chat_id, fmt_cve(text.strip().upper()))
    elif action == "vendor":
        send(chat_id, fmt_vendor(text.strip()))
    elif action == "hash":
        send(chat_id, fmt_hash(text.strip()))
    elif action == "ai":
        send(chat_id, "🤖 thinking…")
        send(chat_id, ask_analyst(text))
    else:
        # Unprompted text: treat it as a question to the analyst, since that is
        # what a person typing into a bot usually means.
        send(chat_id, "🤖 thinking…")
        send(chat_id, ask_analyst(text))


def allowed(uid: int) -> bool:
    return not ALLOWED or str(uid) in ALLOWED


def main() -> int:
    if not TOKEN:
        print("TELEGRAM_BOT_TOKEN is not set.", file=sys.stderr)
        print("Create a bot with @BotFather, then:\n"
              "    export TELEGRAM_BOT_TOKEN='...'", file=sys.stderr)
        return 2

    me = api("getMe")
    if not me.get("ok"):
        print(f"getMe failed: {me}", file=sys.stderr)
        return 1
    print(f"[bot] running as @{me['result'].get('username')}")
    print(f"[bot] allowed users: {sorted(ALLOWED) or 'everyone'}")
    print(f"[bot] analyst: {'hermes' if hermes_available() else 'fallback'}")

    offset = 0
    while True:
        try:
            upd = api("getUpdates", offset=offset, timeout=POLL_TIMEOUT)
            if not upd.get("ok"):
                time.sleep(5)
                continue
            for u in upd.get("result", []):
                offset = u["update_id"] + 1
                try:
                    if "callback_query" in u:
                        cb = u["callback_query"]
                        uid = cb["from"]["id"]
                        chat_id = cb["message"]["chat"]["id"]
                        if not allowed(uid):
                            answer_cb(cb["id"], "not authorized")
                            continue
                        data = cb.get("data", "")
                        if data.startswith("act:"):
                            handle_action(chat_id, data[4:], cb["id"])
                    elif "message" in u:
                        m = u["message"]
                        uid = m["from"]["id"]
                        chat_id = m["chat"]["id"]
                        if not allowed(uid):
                            send(chat_id, "⛔ not authorized")
                            continue
                        text = (m.get("text") or "").strip()
                        if text.startswith("/start") or text.startswith("/menu"):
                            PENDING.pop(chat_id, None)
                            send(chat_id, "<b>Leviathan</b>\n"
                                          "Pick a lookup:", MENU)
                        elif text == "/about":
                            send(chat_id, fmt_about())
                        elif text:
                            handle_text(chat_id, text)
                except Exception as e:  # noqa: BLE001
                    print(f"[bot] handler error: {type(e).__name__}: {e}",
                          file=sys.stderr)
        except KeyboardInterrupt:
            print("\n[bot] stopped")
            return 0
        except Exception as e:  # noqa: BLE001
            print(f"[bot] poll error: {type(e).__name__}: {e}", file=sys.stderr)
            time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
