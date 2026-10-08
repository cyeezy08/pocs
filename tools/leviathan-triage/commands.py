"""Command handlers - pure-ish functions returning Discord embeds.

Shared by three frontends: slash commands (gateway), the CLI, and tests.
Feeds/IO are injected; handlers never print and never touch the network
beyond the Feeds layer they are handed.
"""
from __future__ import annotations

from typing import Optional

from . import config
from .models import Asset, tokenize
from .score import score_finding

HELP_EMBED = {
    "title": "leviathan-triage",
    "description": (
        f"{config.POSITIONING}\n\n"
        "**Commands**\n"
        "- `/triage-cve cve:CVE-2024-3400` - one CVE: EPSS, KEV status, band\n"
        "- `/triage-product product:Ivanti Connect Secure` - product vs KEV\n"
        "- `/kev-today` - newest KEV additions\n"
        "- `/queue` - the prioritized queue for registered assets\n"
        "- `/subscribe license:…` - activate the realtime P0/P1 feed (private)\n"
        "- `/subscription` - your feed status (private)\n\n"
        "Free channel gets the daily digest; subscribers get P0/P1 the minute "
        "the feeds move.\n\n"
        f"_{config.DISCLAIMER}_"
    ),
    "color": config.BAND_COLORS["P3"],
    "footer": {"text": "queue in full at leviathan.ac"},
}


def _error_embed(msg: str) -> dict:
    return {"title": "triage error", "description": msg[:500],
            "color": config.BAND_COLORS["P0"]}


def _sub_embed(title: str, msg: str, ok: bool = True) -> dict:
    return {"title": title[:250], "description": msg[:1500],
            "color": config.BAND_COLORS["P1"] if ok else config.BAND_COLORS["P0"]}


def cmd_subscribe(license_key: str, paywall, discord_id: str,
                  username: str = "user") -> dict:
    """Gumroad license -> subscriber role. ALWAYS rendered ephemeral."""
    if paywall is None:
        return _sub_embed(
            "feed subscriptions",
            "the paywall is not configured on this deployment "
            f"(set {config.ENV_GUMROAD_PERMALINK}). Free digest only for now.",
            ok=False)
    res = paywall.subscribe(license_key, discord_id, username)
    if not res["ok"]:
        return _sub_embed("subscription failed", res["message"], ok=False)
    msg = res["message"]
    if res.get("email"):
        msg += f"\naccount: {res['email']}"
    if res.get("role_error"):
        msg += (f"\n\nsubscription recorded, but the role could not be granted: "
                f"{res['role_error']}\nping the admin - you are on the books.")
    return _sub_embed("feed active", msg)


def cmd_subscription(paywall, discord_id: str) -> dict:
    """Caller's subscription status. ALWAYS rendered ephemeral."""
    if paywall is None:
        return _sub_embed("subscription", "no paywall configured on this deployment.",
                          ok=False)
    st = paywall.status(discord_id)
    if not st.get("active"):
        reason = st.get("reason")
        msg = "no active subscription.\n"
        if reason:
            msg += f"last check failed: {reason}\n"
        msg += "activate with `/subscribe license:…` (key from your Gumroad receipt)."
        return _sub_embed("subscription", msg, ok=False)
    msg = (f"active - {st.get('product') or 'P0 feed'}"
           f"{' since ' + st['since'] if st.get('since') else ''}")
    return _sub_embed("subscription", msg)


def interaction_options(d: dict) -> dict:
    return {o.get("name"): o.get("value") for o in (d.get("data") or {}).get("options", [])}


def cmd_help() -> dict:
    return HELP_EMBED


def cmd_triage_cve(cve: str, feeds) -> dict:
    cve = cve.strip().upper()
    if not cve.startswith("CVE-"):
        return _error_embed(f"`{cve}` does not look like a CVE id (expected CVE-YYYY-NNNN)")
    try:
        epss = feeds.epss().get(cve)
        entry = feeds.kev().get(cve)
    except Exception as e:  # noqa: BLE001 - surfaces feed failure honestly
        return _error_embed(f"feed sync failed: {e}")
    if entry is None and epss is None:
        return _error_embed(f"{cve} is in neither KEV nor the EPSS model - "
                            "unknown, not safe. Verify on NVD before acting.")
    nvd = {}
    try:
        nvd = feeds.nvd_batch([cve], delay=0).get(cve, {})
    except Exception:  # noqa: BLE001
        nvd = {"error": "enrichment skipped"}
    f = score_finding(cve, Asset(identifier="direct lookup"), entry, epss, nvd,
                      match_confidence="direct")
    from .discord import finding_embed
    e = finding_embed(f)
    e["title"] = f"{f.band} · {cve} · score {f.score:g}"
    return e


def _kev_product_search(query: str, kev: dict) -> list:
    """Ranked KEV entries for a free-text product query.

    Two paths, in trust order:
      exact  - product tokens fully contained in the query or vice versa
      ranked - vendor token agreement AND >=1 product/description token hit
               (catches "palo alto globalprotect" -> KEV product "PAN-OS",
               where GlobalProtect appears only in the description)
    Vendor agreement on the ranked path keeps "chromium" from matching
    entries that merely live near "Chrome". Newest first within equal rank.
    """
    q = tokenize(query)
    if not q:
        return []
    exact, ranked = [], []
    for entry in kev.values():
        vendor_toks = tokenize(entry.vendor_project)
        prod_toks = tokenize(entry.product)
        if prod_toks and (prod_toks <= q or q <= prod_toks):
            exact.append(entry)
            continue
        vendor_hit = bool(vendor_toks & q)
        overlap = len((prod_toks | tokenize(entry.short_description)) & q)
        if vendor_hit and overlap:
            ranked.append((overlap, entry))
    ranked.sort(key=lambda t: t[1].date_added, reverse=True)  # newest first
    ranked.sort(key=lambda t: -t[0])                          # then by overlap
    exact.sort(key=lambda e: e.date_added, reverse=True)
    return exact + [e for _, e in ranked]


def cmd_triage_product(product: str, feeds, limit: int = 5) -> dict:
    try:
        kev = feeds.kev()
        epss = feeds.epss()
    except Exception as e:  # noqa: BLE001
        return _error_embed(f"feed sync failed: {e}")
    entries = _kev_product_search(product, kev)
    if not entries:
        return {
            "title": f"no KEV matches for “{product}”",
            "description": ("Nothing in CISA KEV names this product. That is "
                            "exploited-in-the-wild context only - not a clean "
                            "bill of health. Run the full correlation at leviathan.ac."),
            "color": config.BAND_COLORS["P3"],
        }
    fields = []
    asset = Asset(identifier=product, keywords=[product])
    for entry in entries[:limit]:
        f = score_finding(entry.cve, asset, entry, epss.get(entry.cve), {},
                          match_confidence="keyword")
        fields.append({
            "name": f"{f.band} · {entry.cve} · score {f.score:g}"
                    + (" · ransomware" if entry.known_ransomware else ""),
            "value": (entry.short_description[:180] + "…") if len(entry.short_description) > 180
                     else entry.short_description,
        })
    more = len(entries) - limit
    if more > 0:
        fields.append({"name": f"… +{more} more KEV entries",
                       "value": "narrow the product string to focus"})
    return {
        "title": f"“{product}” vs CISA KEV - {len(entries)} matches",
        "description": "Sorted by KEV date (newest first). "
                       "Product-level match; versions are not verified.",
        "color": config.BAND_COLORS.get(fields[0]["name"][:2], 0xE67E22),
        "fields": fields,
        "footer": {"text": f"sources: {feeds.kev_source()} · EPSS model {feeds.epss_model_date()}"},
    }


def cmd_kev_today(feeds, limit: int = 10) -> dict:
    try:
        newest = feeds.kev_newest(limit=limit)
        total = len(feeds.kev())
    except Exception as e:  # noqa: BLE001
        return _error_embed(f"feed sync failed: {e}")
    if not newest:
        return _error_embed("KEV catalog empty - feed sync failed?")
    latest_date = newest[0].date_added
    fields = []
    for e in newest:
        if e.date_added != latest_date and len(fields) >= 5:
            break
        fields.append({
            "name": f"{e.cve} - {e.vendor_project}/{e.product}"
                    + (" · ransomware" if e.known_ransomware else ""),
            "value": (e.short_description[:180] + "…") if len(e.short_description) > 180
                     else e.short_description,
        })
    return {
        "title": f"KEV newest additions ({latest_date}) - catalog {total} CVEs",
        "color": config.BAND_COLORS["P1"],
        "fields": fields,
        "footer": {"text": f"source: {feeds.kev_source()} · triage vs your stack: /queue"},
    }


def cmd_queue(feeds, assets: Optional[list] = None, top: int = 15) -> dict:
    """Queue as one embed: summary + top findings with one-line whys."""
    if not assets:
        return _error_embed("no assets registered - run `init-assets` and edit "
                            "the file, or set LT_ASSETS")
    from .score import build_queue
    try:
        kev = feeds.kev()
        epss = feeds.epss()
    except Exception as e:  # noqa: BLE001
        return _error_embed(f"feed sync failed: {e}")
    findings = build_queue(assets, kev, epss)
    counts: dict = {}
    for f in findings:
        counts[f.band] = counts.get(f.band, 0) + 1
    header = " · ".join(f"{b}×{counts[b]}" for b in config.BANDS if b in counts)
    lines = []
    for f in findings[:top]:
        lines.append(f"**{f.band} {f.score:g}** - {f.summary()}")
    if len(findings) > top:
        lines.append(f"… +{len(findings) - top} more (CLI: `triage --json`)")
    body = "\n".join(lines) or "nothing matched - either a quiet surface or a thin inventory"
    color = config.BAND_COLORS.get(
        next((b for b in ("P0", "P1", "P2", "P3") if b in counts), None), 0x95A5A6)
    return {
        "title": f"queue - {len(findings)} findings ({header or 'none'})",
        "description": body[:4000],
        "color": color,
        "footer": {"text": f"sources: {feeds.kev_source()} · EPSS {feeds.epss_model_date()} · {config.DISCLAIMER[:120]}"},
    }


def _discord_user(d: dict) -> tuple:
    """(user_id, username) from a guild or DM interaction payload."""
    member = d.get("member") or {}
    user = member.get("user") or d.get("user") or {}
    return str(user.get("id", "")), user.get("username", "user")


def respond_to_interaction(d: dict, feeds, assets: Optional[list] = None,
                           paywall=None) -> dict:
    """Dispatch an INTERACTION_CREATE payload -> callback data {'embeds': [...]}.

    subscribe/subscription responses carry flags=64 (ephemeral) so license
    keys never land in a channel everyone can read.
    """
    name = (d.get("data") or {}).get("name", "")
    opts = interaction_options(d)
    try:
        if name == "triage-cve":
            return {"embeds": [cmd_triage_cve(opts.get("cve", ""), feeds)]}
        if name == "triage-product":
            return {"embeds": [cmd_triage_product(opts.get("product", ""), feeds)]}
        if name == "kev-today":
            return {"embeds": [cmd_kev_today(feeds)]}
        if name == "queue":
            return {"embeds": [cmd_queue(feeds, assets)]}
        if name == "subscribe":
            user_id, username = _discord_user(d)
            return {"flags": config.EPHEMERAL_FLAGS,
                    "embeds": [cmd_subscribe(opts.get("license", ""), paywall,
                                             user_id, username)]}
        if name == "subscription":
            user_id, _ = _discord_user(d)
            return {"flags": config.EPHEMERAL_FLAGS,
                    "embeds": [cmd_subscription(paywall, user_id)]}
        return {"embeds": [cmd_help()]}
    except Exception as e:  # noqa: BLE001 - never let an interaction hang
        return {"embeds": [_error_embed(f"handler failed: {e}")]}
