"""Public HTTP response metadata. No forms, no auth, no crawling."""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import requests

from bdosint.core.http import redact

log = logging.getLogger("bdosint")


def collect_http_metadata(http, url: str) -> dict[str, Any]:
    """Single GET; record public metadata and redirect chain only."""
    result: dict[str, Any] = {"url": url}
    try:
        start = time.monotonic()
        resp = http.session.get(url, timeout=http.timeout, allow_redirects=True)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        chain = [h.url for h in list(resp.history) + [resp]]

        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:20000],
                      re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()[:200]

        result.update({
            "status_code": resp.status_code,
            "final_url": resp.url,
            "redirect_chain": chain,
            "content_type": resp.headers.get("Content-Type", ""),
            "content_length": resp.headers.get("Content-Length") or str(len(resp.content)),
            "server": resp.headers.get("Server", ""),
            "cache_headers": {
                k: v for k, v in resp.headers.items()
                if k.lower() in ("cache-control", "expires", "etag", "last-modified",
                                 "x-cache", "cf-cache-status")
            },
            "title": redact(title),
            "response_time_ms": elapsed_ms,
        })
        return result
    except requests.exceptions.SSLError as exc:
        result["error"] = f"ssl error: {exc}"
    except requests.exceptions.Timeout:
        result["error"] = f"timeout after {http.timeout}s"
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"connection error: {exc}"
    except requests.exceptions.RequestException as exc:
        result["error"] = f"request error: {exc}"
    return result
