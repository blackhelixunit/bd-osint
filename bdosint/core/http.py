"""Shared, conservative HTTP client with redaction and error safety."""

from __future__ import annotations

import re
from typing import Any

import requests

from bdosint.core.cache import FileCache
from bdosint.core.rate_limiter import RateLimiterRegistry

USER_AGENT = "BD-OSINT/3.0 (+passive research; respectful of robots & rate limits)"

_REDACT_PATTERNS = re.compile(
    r"(?i)\b(password|passwd|secret|api_key|apikey|token|authorization)\b(\s*[=:]\s*)[^\s&\"',]+"
)


def redact(text: str) -> str:
    """Redact obvious credential-like values in evidence text."""
    if not isinstance(text, str):
        return text
    return _REDACT_PATTERNS.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)


class HttpClient:
    """Small wrapper around requests with rate limiting, caching, safe errors."""

    def __init__(
        self,
        timeout: float = 15.0,
        delay: float = 1.5,
        cache: FileCache | None = None,
        max_concurrency: int = 5,
    ) -> None:
        self.timeout = timeout
        self.cache = cache
        self.rate = RateLimiterRegistry(delay)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
        self.session.max_redirects = 10
        self.max_concurrency = max_concurrency

    def get_json(self, url: str, provider: str, params: dict | None = None) -> tuple[Any | None, str | None]:
        """GET JSON with cache + rate limit. Returns (data, error)."""
        cache_key = f"{url}?{params or ''}"
        if self.cache:
            cached = self.cache.get(provider, cache_key)
            if cached is not None:
                return cached, None
        try:
            self.rate.get(provider).wait()
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 429:
                return None, f"rate limited by provider (HTTP 429) for {url}"
            if resp.status_code == 404:
                return None, "not found (404)"
            resp.raise_for_status()
            data = resp.json()
            if self.cache:
                self.cache.set(provider, cache_key, data)
            return data, None
        except requests.exceptions.Timeout:
            return None, f"timeout after {self.timeout}s"
        except requests.exceptions.SSLError as exc:
            return None, f"ssl error: {exc}"
        except requests.exceptions.ConnectionError as exc:
            return None, f"connection error: {exc}"
        except ValueError:
            return None, "invalid JSON from provider"
        except requests.exceptions.RequestException as exc:
            return None, f"http error: {exc}"

    def get_text(self, url: str, provider: str = "http") -> tuple[str | None, int | None, str | None]:
        """GET text content. Returns (text, status, error). Never authenticates."""
        try:
            self.rate.get(provider).wait()
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 429:
                return None, 429, "rate limited (429)"
            if resp.status_code in (403, 404):
                return None, resp.status_code, f"HTTP {resp.status_code}"
            resp.raise_for_status()
            return resp.text, resp.status_code, None
        except requests.exceptions.Timeout:
            return None, None, f"timeout after {self.timeout}s"
        except requests.exceptions.RequestException as exc:
            return None, None, f"request error: {exc}"
