"""Single source of truth - version, defaults, store layout.

No numbers or paths hand-typed anywhere else. (Never-Again Kit rule.)
"""
import os

VERSION = "0.1.0"
TOOL = "surfacediff"
TAGLINE = "snapshot and diff your external attack surface"

# Store layout
DEFAULT_DIR = ".surfacediff"
ENV_DIR = "SURFACEDIFF_DIR"
POINTER_NAME = "current"
META_KEY = "_meta"

# Snapshot format version - bump when record shape changes
SNAPSHOT_FORMAT = 1

# Exit codes (CI contract: cron/pipeline alerts on CHANGES=1)
EXIT_OK = 0
EXIT_CHANGES = 1
EXIT_ERROR = 2

# Pass-through attrs per source tool (subset kept per record)
HTTPX_ATTRS = ("status_code", "title", "webserver", "tech", "cdn", "asn", "csp")
NAABU_ATTRS = ("ip", "host")
