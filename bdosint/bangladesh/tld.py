"""Bangladesh TLD recognition and classification."""

from __future__ import annotations

from dataclasses import dataclass

BD_SECOND_LEVEL = {
    ".com.bd": "Commercial",
    ".gov.bd": "Government",
    ".edu.bd": "Education",
    ".ac.bd": "Academic",
    ".org.bd": "Organization",
    ".net.bd": "Network",
}

SENSITIVE_CATEGORIES = {"Government", "Education", "Academic"}


@dataclass
class BDTLDInfo:
    is_bd: bool
    tld: str | None
    category: str | None
    sensitive: bool


def classify(domain: str) -> BDTLDInfo:
    """Classify a domain against the .bd TLD tree (longest label first)."""
    d = (domain or "").lower().rstrip(".")
    for sld in sorted(BD_SECOND_LEVEL, key=len, reverse=True):
        if d.endswith(sld) or d == sld.lstrip("."):
            category = BD_SECOND_LEVEL[sld]
            return BDTLDInfo(True, sld, category, category in SENSITIVE_CATEGORIES)
    if d == "bd" or d.endswith(".bd"):
        return BDTLDInfo(True, ".bd", "Country TLD", False)
    return BDTLDInfo(False, None, None, False)


def conservative_delay(base_delay: float, info: BDTLDInfo) -> float:
    """Raise request delay for government/education/academic targets."""
    return max(base_delay, 3.0) if info.sensitive else base_delay
