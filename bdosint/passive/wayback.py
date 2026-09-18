"""Historical URLs from the public Wayback CDX API. Categorized + redacted."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import unquote

from bdosint.core.http import redact

log = logging.getLogger("bdosint")

CDX_URL = "https://web.archive.org/cdx/search/cdx"

CATEGORY_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("AUTH", re.compile(r"(?i)/(login|signin|sign-in|auth|session|logout|register|signup)(/|\?|$)")),
    ("API", re.compile(r"(?i)/(api|graphql|rest|v1|v2|v3)(/|\?|$)")),
    ("DOCUMENT", re.compile(r"(?i)/(docs?|documentation|manual|guide|whitepaper|report|download)(/|\?|$|\.)")),
    ("BACKUP-LIKE", re.compile(r"(?i)\.(bak|backup|old|orig|save|sql|dump|tar|tar\.gz|tgz|zip|7z)(\?|$)")),
    ("CONFIGURATION-LIKE", re.compile(r"(?i)(/\.env|/\.git/|\.conf$|\.config$|\.ini$|\.yml$|\.yaml$|\.xml$|/config|/settings|/phpinfo)")),
    ("STATIC", re.compile(r"(?i)\.(css|js|jpg|jpeg|png|gif|svg|ico|woff2?|ttf|mp4|mp3)(\?|$)")),
]


def categorize(url: str) -> str:
    for category, pattern in CATEGORY_RULES:
        if pattern.search(url):
            return category
    return "OTHER"


def collect(domain: str, http, limit: int = 500) -> dict[str, Any]:
    """Query CDX for historical URLs. Content never downloaded."""
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original,timestamp,statuscode",
        "collapse": "urlkey",
        "limit": str(limit),
    }
    data, err = http.get_json(CDX_URL, provider="wayback", params=params)
    if err:
        return {"error": err, "urls": []}
    if not isinstance(data, list) or len(data) < 2:
        return {"urls": [], "categories": {}}

    entries: list[dict[str, str]] = []
    category_counts: dict[str, int] = {}
    for row in data[1:]:
        if len(row) < 3:
            continue
        url, timestamp, status = row[0], row[1], row[2]
        category = categorize(url)
        category_counts[category] = category_counts.get(category, 0) + 1
        entries.append({"url": redact(url), "timestamp": timestamp,
                        "status": status, "category": category})
    interesting = [e for e in entries if e["category"] in
                   ("AUTH", "API", "DOCUMENT", "BACKUP-LIKE", "CONFIGURATION-LIKE")]
    return {
        "urls": entries,
        "interesting": _second_pass_redact(interesting)[:100],
        "categories": category_counts,
    }


def _second_pass_redact(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    """Also mask token-like query values."""
    token_pat = re.compile(r"(?i)([?&][^=]*(token|key|secret|password|passwd)[^=]*=)[^&]+")
    out = []
    for e in entries:
        e = dict(e)
        e["url"] = token_pat.sub(r"\1[REDACTED]", unquote(e["url"]))
        out.append(e)
    return out
