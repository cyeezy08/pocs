"""Data models - dataclasses only, stdlib, no magic."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import config


def normalize(s: str) -> str:
    """Lowercase, underscores/hyphens -> spaces, collapse whitespace."""
    return " ".join(s.lower().replace("_", " ").replace("-", " ").split())


def tokenize(s: str) -> set:
    """Normalized word tokens ("Exchange Server" -> {"exchange", "server"})."""
    return {t for t in normalize(s).split() if t}


@dataclass
class Asset:
    """Software you declare you run. The bot sends nothing to it - ever."""
    identifier: str                  # host, service label, or your own tag
    vendor: Optional[str] = None     # e.g. "ivanti"
    product: Optional[str] = None    # e.g. "connect secure"
    version: Optional[str] = None    # recorded as evidence, never verified
    cpe: Optional[str] = None        # raw cpe:2.3 string if you have one
    keywords: list = field(default_factory=list)
    source: str = "manual"           # manual | httpx | hostage | ...

    def match_tokens(self) -> set:
        toks: set = set()
        if self.vendor:
            toks.update(tokenize(self.vendor))
        if self.product:
            toks.update(tokenize(self.product))
        for kw in self.keywords:
            toks.update(tokenize(kw))
        return toks


@dataclass
class KevEntry:
    cve: str
    vendor_project: str
    product: str
    date_added: str
    known_ransomware: bool
    short_description: str


@dataclass
class Reason:
    component: str      # match | cvss | epss | kev | poc
    points: float
    evidence: str
    source: str         # provenance, e.g. "CISA KEV"

    def line(self) -> str:
        pts = f"{self.points:g}"
        return f"[{self.component}] +{pts} - {self.evidence} (source: {self.source})"


@dataclass
class Finding:
    cve: str
    asset: Asset
    score: float
    band: str = "P3"
    reasons: list = field(default_factory=list)
    match_confidence: str = "keyword"   # cpe | keyword | direct (no matching)
    epss: Optional[float] = None
    in_kev: bool = False
    kev_date_added: str = ""
    known_ransomware: bool = False
    has_poc: bool = False
    cvss: Optional[float] = None
    title: str = ""

    def flags(self) -> list:
        out = []
        if self.in_kev:
            out.append("KEV")
        if self.known_ransomware:
            out.append("ransomware-associated")
        if self.has_poc:
            out.append("public PoC")
        if self.cvss is not None:
            out.append(f"CVSS {self.cvss:g}")
        return out

    def summary(self) -> str:
        f = f" ({', '.join(self.flags())})" if self.flags() else ""
        return f"{self.cve} on {self.asset.identifier} - {self.band} {self.score:g}{f}"


def band_for(score: float, in_kev: bool, known_ransomware: bool,
             epss: Optional[float], cvss: Optional[float] = None) -> str:
    """Declarative banding, evaluated top-down. See config.BANDS."""
    if in_kev:
        severe = known_ransomware
        if epss is not None and epss >= config.EPSS_P0_THRESHOLD:
            severe = True
        if cvss is not None and cvss >= config.CVSS_P0_THRESHOLD:
            severe = True
        return "P0" if severe else "P1"
    if (epss is not None and epss >= config.EPSS_P2_THRESHOLD) \
            or score >= config.SCORE_P2_MINIMUM:
        return "P2"
    return "P3"
