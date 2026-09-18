"""RFC 9116 security.txt discovery. Missing file is NOT a vulnerability."""

from __future__ import annotations

import logging
from typing import Any

from bdosint.core.http import redact

log = logging.getLogger("bdosint")

INTERESTING_FIELDS = ("Contact", "Policy", "Encryption", "Acknowledgments",
                      "Preferred-Languages", "Expires", "Hiring", "Canonical")

PATHS = ("/.well-known/security.txt", "/security.txt")


def collect(domain: str, http) -> dict[str, Any]:
    """Fetch security.txt over HTTPS only; parse public contact/policy fields."""
    for path in PATHS:
        url = f"https://{domain}{path}"
        text, status, err = http.get_text(url, provider="securitytxt")
        if err or text is None:
            continue
        fields: dict[str, list[str]] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            if key.lower() in {f.lower() for f in INTERESTING_FIELDS}:
                fields.setdefault(key, []).append(redact(value.strip()))
        return {"found": True, "url": url, "fields": fields}
    return {"found": False, "note": "security.txt not published (informational only)"}
