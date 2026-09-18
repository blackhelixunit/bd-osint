"""Security header presence analysis. Missing header = informational, not a vuln."""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("bdosint")

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def analyze(response_headers: dict[str, str]) -> dict[str, Any]:
    """Report present/missing/value for each security header."""
    lowered = {k.lower(): (k, v) for k, v in (response_headers or {}).items()}
    out: dict[str, Any] = {}
    for header in SECURITY_HEADERS:
        hit = lowered.get(header.lower())
        if hit:
            out[header] = {"present": True, "value": hit[1][:300]}
        else:
            out[header] = {"present": False, "value": None,
                           "note": "Security header not observed (informational)"}
    return out
