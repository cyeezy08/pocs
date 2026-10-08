"""Data models - dataclasses only, stdlib, no magic."""
from __future__ import annotations

from dataclasses import dataclass, field


def normalize(s: str) -> str:
    """Lowercase, underscores/hyphens -> spaces, collapse whitespace."""
    return " ".join(s.lower().replace("_", " ").replace("-", " ").split())


def tokenize(s: str) -> set[str]:
    """Normalized word tokens ("Exchange Server" -> {"exchange", "server"})."""
    return {t for t in normalize(s).split() if t}


@dataclass
class Asset:
    """A registered, customer-owned asset. Only assets that exist in an
    inventory WITH a signed attestation ever produce findings."""
    identifier: str                  # domain, host, or asset label
    vendor: str | None = None        # CPE vendor, e.g. "microsoft"
    product: str | None = None       # CPE product, e.g. "exchange_server"
    version: str | None = None
    cpe: str | None = None           # raw cpe:2.3 string if provided
    keywords: list[str] = field(default_factory=list)
    source: str = "manual"           # manual | httpx | subfinder | ...

    def match_tokens(self) -> set[str]:
        """Word-level tokens used for keyword matching. Multi-word keywords
        are split so 'connect secure' contributes {'connect', 'secure'}."""
        toks: set[str] = set()
        if self.vendor:
            toks.update(tokenize(self.vendor))
        if self.product:
            toks.update(tokenize(self.product))
        for kw in self.keywords:
            toks.update(tokenize(kw))
        return toks


@dataclass
class Reason:
    component: str      # cvss | epss | kev | poc | match
    points: float
    evidence: str
    source: str         # feed/source name, e.g. "CISA KEV 2026-09-10"

    def line(self) -> str:
        pts = f"{self.points:g}"
        return f"[{self.component}] +{pts} - {self.evidence} (source: {self.source})"


@dataclass
class Finding:
    cve: str
    asset: Asset
    score: float
    reasons: list[Reason] = field(default_factory=list)
    match_confidence: str = "keyword"   # cpe | keyword
    cvss: float | None = None
    epss: float | None = None
    in_kev: bool = False
    kev_known_ransomware: bool = False
    has_poc_ref: bool = False
    title: str = ""

    def summary(self) -> str:
        flags = []
        if self.in_kev:
            flags.append("KEV")
        if self.kev_known_ransomware:
            flags.append("ransomware-associated")
        if self.has_poc_ref:
            flags.append("public PoC")
        f = f" ({', '.join(flags)})" if flags else ""
        return f"{self.cve} on {self.asset.identifier} - score {self.score:g}{f}"
