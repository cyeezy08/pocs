"""surfacediff - snapshot and diff your external attack surface.

ProjectDiscovery gives you recon tools. surfacediff makes them a
monitoring system: pipe any tool output in, get content-addressed
snapshots back, diff them field-by-field. Zero dependencies. stdlib only.
"""
from . import config

__version__ = config.VERSION
