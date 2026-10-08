"""leviathan-triage - single source of truth.

Rule #1 (Never-Again Kit discipline, inherited from leviathan-core): every
number that shapes output - weights, thresholds, feed URLs, env names,
version - lives HERE. Nothing hand-typed in scoring, alerting, or reporting
code. Tests read these constants, so changing a rule without updating tests
fails loudly.

Product lane (Doug, 2026-09): the ASN-scale play needs infra we do not have.
This bot needs none: it ships zero packets, correlates PUBLIC exploit
intelligence against the software you declare, and pushes the triaged queue
to Discord. Triage is not scanning; scanning stays at leviathan.ac.
"""
import os

VERSION = "0.2.2"
TOOL = "leviathan-triage"
POSITIONING = (
    "The KEV firehose, triaged against YOUR stack, in your Discord. "
    "Zero packets, pure intel."
)
DISCLAIMER = (
    "Pure intelligence correlation against public feeds. This tool sends no "
    "packets to your assets and performs no scanning. Product-level matching: "
    "versions are recorded, never verified. Triage is not a scan."
)
USER_AGENT = f"{TOOL}/{VERSION} (leviathan.ac)"

# ---------------------------------------------------------------------------
# Scoring - the audited Leviathan formula (same contract as leviathan-core):
#   CVSS <= 40 + EPSS <= 40 + KEV 15 + PoC 5, capped at 100
# Components not yet assessed contribute 0 points and SAY SO via a reason.
# ---------------------------------------------------------------------------
WEIGHTS = {
    "cvss": {"max_points": 40, "source": "NVD CVSS v3.1 base score, fetched per matched CVE (--deep)"},
    "epss": {"max_points": 40, "source": "FIRST EPSS probability, bulk daily CSV"},
    "kev": {"points": 15, "source": "CISA Known Exploited Vulnerabilities catalog"},
    "poc": {"max_points": 5, "source": "public PoC reference in NVD references (--deep)"},
}
SCORE_CAP = 100

# ---------------------------------------------------------------------------
# Priority bands. Declarative, evaluated top-down by score.band_for().
# The thesis in one table: KEV = exploited in the wild, so KEV is never
# below P1; ransomware-associated or widely-exploited KEV is P0.
# ---------------------------------------------------------------------------
EPSS_P0_THRESHOLD = 0.50   # KEV + EPSS >= this => P0
EPSS_P2_THRESHOLD = 0.25   # not in KEV but EPSS >= this => P2
SCORE_P2_MINIMUM = 50      # not in KEV but score >= this => P2
CVSS_P0_THRESHOLD = 9.0    # only applied in deep mode (CVSS actually assessed)

BANDS = ("P0", "P1", "P2", "P3")
BAND_MEANING = {
    "P0": "exploited in the wild and severe - act today",
    "P1": "confirmed exploited in the wild (CISA KEV) - patch this week",
    "P2": "high exploitability signal - schedule",
    "P3": "context noise for now - re-check on next feed sync",
}
BAND_COLORS = {  # Discord embed integer colors
    "P0": 0xE74C3C,  # red
    "P1": 0xE67E22,  # orange
    "P2": 0xF1C40F,  # yellow
    "P3": 0x95A5A6,  # grey
}

# ---------------------------------------------------------------------------
# Feeds (public, keyless for the core loop)
# ---------------------------------------------------------------------------
FEEDS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "kev_mirror": "https://kevin.gtfkd.com/kev",
    "epss": "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
}
# Cache TTLs (seconds). KEV updates ~daily; EPSS is a daily model.
KEV_TTL_SECONDS = 6 * 3600
EPSS_TTL_SECONDS = 24 * 3600
# NVD polite rate without an API key: ~5 requests / 30s.
NVD_DELAY_SECONDS_NO_KEY = 6.5

# Reference keywords that count as public-PoC evidence (kept narrow on purpose)
POC_REF_KEYWORDS = ("exploit", "poc", "proof of concept", "github.com", "metasploit")

# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
MATCH_CONFIDENCE = ("cpe", "keyword")   # descending trust

# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------
ENV_WEBHOOK = "LT_DISCORD_WEBHOOK"      # webhook URL - the 5-minute path (free lane)
ENV_WEBHOOK_PAID = "LT_DISCORD_WEBHOOK_PAID"  # subscriber-only lane (P0/P1 realtime)
ENV_BOT_TOKEN = "LT_DISCORD_BOT_TOKEN"  # full gateway bot - the native path
ENV_APP_ID = "LT_DISCORD_APP_ID"        # application id for command registration
ENV_ASSETS = "LT_ASSETS"                # default assets file
ENV_STATE_DIR = "LT_STATE_DIR"          # default cache+state root
DEFAULT_STATE_DIR = os.path.expanduser("~/.leviathan-triage")
WEBHOOK_EMBED_LIMIT = 10                # Discord allows <= 10 embeds per message
MAX_QUEUE_PREVIEW = 10                  # embeds rendered per digest

# ---------------------------------------------------------------------------
# Paywall - the feed business: free daily digest is the marketing,
# P0/P1 realtime lane is the product, Gumroad license keys are the gate.
# ---------------------------------------------------------------------------
ENV_GUMROAD_PERMALINK = "LT_GUMROAD_PERMALINK"  # gumroad product permalink - unset = paywall off
ENV_BUY_URL = "LT_BUY_URL"                      # checkout link shown in the free-digest CTA
ENV_DISCORD_GUILD_ID = "LT_DISCORD_GUILD_ID"    # guild where the subscriber role lives
ENV_DISCORD_ROLE_ID = "LT_DISCORD_ROLE_ID"      # role granted to paid subscribers
GUMROAD_VERIFY_URL = "https://api.gumroad.com/v2/licenses/verify"
GUMROAD_TIMEOUT_SECONDS = 30.0
DISCORD_API_BASE = "https://discord.com/api/v10"
EPHEMERAL_FLAGS = 64              # interaction callback flag: only the invoker sees it
SUBSCRIBER_BANDS = ("P0", "P1")   # bands that hit the paid lane in realtime
LICENSE_MIN_LENGTH = 8            # gumroad keys are long; this only rejects paste garbage
SUBSCRIBE_HELP_URL = "https://gumroad.com"  # shown in help when paywall configured

# ---------------------------------------------------------------------------
# Huginn - the X/Twitter auto-poster (the marketing raven).
# Huginn flies out (posts the daily P0 digest), Muninn remembers (the feeds).
# OAuth 1.0a user context, signed with stdlib only. Keys NEVER touch code.
# ---------------------------------------------------------------------------
ENV_X_CONSUMER_KEY = "LT_X_CONSUMER_KEY"      # developer.x.com app consumer key
ENV_X_CONSUMER_SECRET = "LT_X_CONSUMER_SECRET"
ENV_X_ACCESS_TOKEN = "LT_X_ACCESS_TOKEN"      # portal -> Keys and tokens -> OAuth 1.0a Access Token
ENV_X_ACCESS_SECRET = "LT_X_ACCESS_SECRET"
ENV_X_LINK = "LT_X_LINK"                      # link appended to posts (Discord invite)
X_POST_MAX_CHARS = 280
X_URL_DISPLAY_CHARS = 23                       # t.co wrapping - how X charges for URLs
X_API_BASE = "https://api.twitter.com"
X_TWEET_ENDPOINT = f"{X_API_BASE}/2/tweets"
X_ME_ENDPOINT = f"{X_API_BASE}/2/users/me"
X_REQUEST_TOKEN_ENDPOINT = f"{X_API_BASE}/oauth/request_token"
X_TIMEOUT_SECONDS = 30.0

# Slash commands (name, description, options). Registered via register-commands.
SLASH_COMMANDS = (
    {"name": "triage-cve",
     "description": "Triage one CVE: EPSS, KEV status, priority band",
     "options": [{"name": "cve", "description": "CVE id, e.g. CVE-2024-3400",
                  "type": 3, "required": True}]},
    {"name": "triage-product",
     "description": "Triage a product string against the KEV catalog",
     "options": [{"name": "product", "description": "e.g. Ivanti Connect Secure",
                  "type": 3, "required": True}]},
    {"name": "kev-today",
     "description": "Newest additions to the CISA KEV catalog"},
    {"name": "queue",
     "description": "Prioritized queue for this server's registered assets"},
    {"name": "subscribe",
     "description": "Activate the realtime P0 feed with your Gumroad license key",
     "options": [{"name": "license",
                  "description": "License key from your Gumroad receipt (private reply)",
                  "type": 3, "required": True}]},
    {"name": "subscription",
     "description": "Show your feed subscription status (private reply)"},
    {"name": "help",
     "description": "What this bot does and how honest it is"},
)

# CLI commands that need no Discord wiring ( tweeting is CLI/timer only )
X_DAILY_POSTS = 1  # free tier is generous for writes; cadence stays 1/day on purpose
