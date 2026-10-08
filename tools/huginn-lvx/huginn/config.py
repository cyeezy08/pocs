"""Huginn LVX - single source of truth for env names, limits, templates."""

from __future__ import annotations

import os

ENV_GH_USER = "HUG_GH_USER"
ENV_X_KEY = "HUG_X_API_KEY"
ENV_X_SECRET = "HUG_X_API_SECRET"
ENV_X_TOKEN = "HUG_X_ACCESS_TOKEN"
ENV_X_TOKEN_SECRET = "HUG_X_ACCESS_SECRET"
ENV_TG_TOKEN = "HUG_TG_TOKEN"
ENV_TG_CHAT = "HUG_TG_CHAT"
ENV_STATE_DIR = "HUG_STATE_DIR"
ENV_EVENTS_URL = "HUG_EVENTS_URL"  # override for tests / mirrors of the GH API

MAX_POST_CHARS = 280          # X weighted limit
URL_WEIGHT = 23               # t.co wraps any URL to a fixed weighted 23
MIN_POST_INTERVAL_SEC = 60 * 15   # X automation rules: no duplicate/flood; >=15 min between posts
MAX_DRAFTS_PER_RUN = 5        # never draft more than 5 posts per fetch cycle

X_TWEET_URL = "https://api.twitter.com/2/tweets"
X_OAUTH_PARAMS = {
    "oauth_signature_method": "HMAC-SHA1",
    "oauth_version": "1.0",
}
X_OAUTH_REALM_DEFAULT = ""

TG_SEND_URL = "https://api.telegram.org/bot{token}/sendMessage"

EXIT_OK = 0
EXIT_NOTHING = 1
EXIT_ERROR = 2

# Post templates. {url} is replaced with a t.co-weighted placeholder at render time.
TEMPLATES = {
    "release": "\U0001F6A8 {repo} {tag} is out \u2014 {summary}\n{url}\n#infosec #bugbounty #opensource",
    "newrepo": "\U0001F5C2 new drop: {repo} \u2014 {summary}\n{url}\n#infosec #bugbounty",
    "push": "\u2699\uFE0F {repo}: {n} new commits \u2014 {summary}\n{url}\n#infosec #coding",
    "pushhtml": "\U0001F527 {repo} updated \u2014 {summary}\n{url}\n#infosec",
    "public": "\U0001F4C2 {repo} is now public \u2014 {summary}\n{url}\n#infosec #opensource",
}
DEFAULT_SUMMARY = "code is code. details in the repo."
