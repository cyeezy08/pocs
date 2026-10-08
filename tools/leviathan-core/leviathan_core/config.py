"""Leviathan Core - single source of truth.

Rule #1 (Never-Again Kit, ported from the TS kit): every number that shapes
output - weights, caps, feed URLs, version - lives HERE. Nothing hand-typed
in scoring or reporting code. Tests read these constants, so changing a
weight without updating tests fails CI loudly.
"""

# ---------------------------------------------------------------------------
# Scoring weights - from the audited v1 correlation formula:
#   CVSS <= 40 + EPSS <= 40 + KEV 15 + PoC 5, capped at 100
# Every component records its reason; a finding without reasons is a bug.
# ---------------------------------------------------------------------------
WEIGHTS = {
    "cvss": {"max_points": 40, "source": "NVD CVSS v3.1 base score, fetched per matched CVE"},
    "epss": {"max_points": 40, "source": "FIRST EPSS probability, bulk daily CSV"},
    "kev": {"points": 15, "source": "CISA Known Exploited Vulnerabilities catalog"},
    "poc": {"points": 5, "source": "public PoC reference found in NVD references"},
}
SCORE_CAP = 100

# EPSS probability [0..1] scaled to WEIGHTS['epss']['max_points']
# CVSS base [0..10] scaled to WEIGHTS['cvss']['max_points'] (base/10 * 40)

# ---------------------------------------------------------------------------
# Feed URLs (public, no keys required for the core loop)
# ---------------------------------------------------------------------------
FEEDS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",  # per-CVE, on demand, cached
}

# NVD polite rate without an API key: ~5 requests / 30s. Set NVD_API_KEY env
# to go faster. We degrade gracefully: no CVSS => 0 points, honest reason.
NVD_DELAY_SECONDS_NO_KEY = 6.5

# Reference keywords that count as public-PoC evidence (kept narrow on purpose)
POC_REF_KEYWORDS = ("exploit", "poc", "proof of concept", "github.com", "metasploit")

# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
# confidence levels produced by match.py, in descending trust order
MATCH_CONFIDENCE = ("cpe", "keyword")
# normalized-token overlap required for a "keyword" match
KEYWORD_MIN_TOKENS = 1

# ---------------------------------------------------------------------------
# Product identity gates (from PROJECT_AUDIT.md):
# passive intelligence only in v0. No active scanning ships from this package.
# ---------------------------------------------------------------------------
PASSIVE_ONLY = True
REQUIRED_ATTESTATION = "authorized"  # inventory must declare this, verbatim

VERSION = "0.1.0"
TOOL = "leviathan-core"
POSITIONING = (
    "Leviathan Core correlates your registered assets against public exploit "
    "intelligence and returns an explainable proof-of-exposure queue."
)
DISCLAIMER = (
    "Passive correlation against public feeds only. No active scanning is "
    "performed by this tool. Scores are triage signals, not guarantees."
)
