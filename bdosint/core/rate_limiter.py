"""Per-provider rate limiting with conservative defaults."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Simple thread-safe minimum-interval rate limiter."""

    def __init__(self, delay: float = 1.5) -> None:
        self.delay = max(0.0, delay)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            remaining = self.delay - (now - self._last)
            if remaining > 0:
                time.sleep(remaining)
            self._last = time.monotonic()


class RateLimiterRegistry:
    """One limiter per provider name."""

    def __init__(self, default_delay: float = 1.5) -> None:
        self._default_delay = default_delay
        self._limiters: dict[str, RateLimiter] = {}
        self._lock = threading.Lock()

    def get(self, provider: str, delay: float | None = None) -> RateLimiter:
        with self._lock:
            if provider not in self._limiters:
                self._limiters[provider] = RateLimiter(
                    delay if delay is not None else self._default_delay
                )
            return self._limiters[provider]
