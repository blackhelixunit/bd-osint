"""Technology fingerprinting from public headers and harmless page markers."""

from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger("bdosint")

HEADER_SIGS: dict[str, dict[str, tuple[str, str]]] = {
    "server": {
        "apache": ("Apache", "high"),
        "nginx": ("Nginx", "high"),
        "microsoft-iis": ("IIS", "high"),
        "litespeed": ("LiteSpeed", "high"),
        "cloudflare": ("Cloudflare", "high"),
    },
    "x-powered-by": {
        "php": ("PHP", "high"),
        "asp.net": ("ASP.NET", "high"),
        "express": ("Express", "high"),
        "laravel": ("Laravel", "high"),
    },
}

BODY_SIGS: list[tuple[str, str, str]] = [
    (r"/wp-content/|/wp-includes/", "WordPress", "high"),
    (r'<meta name="generator" content="WordPress', "WordPress", "high"),
    (r"drupal\.js|sites/default/files", "Drupal", "medium"),
    (r"csrfmiddlewaretoken", "Django", "medium"),
    (r"laravel_session", "Laravel", "high"),
    (r"cf-ray|__cfduid|cdn-cgi/", "Cloudflare", "high"),
]

_VERSION_RE = re.compile(r"(?P<tech>apache|nginx|php|asp\.net)[/ ]v?(?P<version>[\d.]+)", re.IGNORECASE)


def detect(headers: dict[str, str], body: str | None = None) -> list[dict[str, Any]]:
    """Detect technologies with confidence. Versions only when directly observed."""
    found: dict[str, dict[str, Any]] = {}

    def record(name: str, where: str, confidence: str, version: str | None = None) -> None:
        entry = found.setdefault(name, {"technology": name, "evidence": [],
                                        "confidence": "low", "version": None})
        entry["evidence"].append(where)
        order = {"low": 0, "medium": 1, "high": 2}
        if order[confidence] > order[entry["confidence"]]:
            entry["confidence"] = confidence
        if version and not entry["version"]:
            entry["version"] = version

    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    for header, sigs in HEADER_SIGS.items():
        value = (lowered.get(header) or "").lower()
        m = _VERSION_RE.search(lowered.get(header, "") or "")
        version = m.group("version") if m else None
        for pat, (tech, conf) in sigs.items():
            if pat in value:
                record(tech, f"{header} header", conf, version if pat in value.lower() else None)

    if body:
        snippet = body[:100000].lower()
        for pat, tech, conf in BODY_SIGS:
            if re.search(pat, snippet, re.IGNORECASE):
                record(tech, "page signature", conf)

    return sorted(found.values(), key=lambda x: x["technology"])
