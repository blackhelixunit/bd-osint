"""Filesystem cache with TTL, partitioned per provider."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

DEFAULT_CACHE_TTL = 86400


class FileCache:
    """TTL-based JSON file cache under <root>/<provider>/."""

    def __init__(self, root: str = "cache", ttl: int = DEFAULT_CACHE_TTL, enabled: bool = True) -> None:
        self.root = Path(root)
        self.ttl = ttl
        self.enabled = enabled
        if enabled:
            for part in ("crtsh", "rdap", "wayback", "dns", "http"):
                (self.root / part).mkdir(parents=True, exist_ok=True)

    def _path(self, provider: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()[:40]
        return self.root / provider / f"{digest}.json"

    def get(self, provider: str, key: str) -> Any | None:
        if not self.enabled:
            return None
        path = self._path(provider, key)
        try:
            with path.open("r", encoding="utf-8") as fh:
                entry = json.load(fh)
            if time.time() - entry["ts"] > self.ttl:
                path.unlink(missing_ok=True)
                return None
            return entry["data"]
        except (OSError, KeyError, ValueError):
            return None

    def set(self, provider: str, key: str, data: Any) -> None:
        if not self.enabled:
            return
        path = self._path(provider, key)
        try:
            with path.open("w", encoding="utf-8") as fh:
                json.dump({"ts": time.time(), "data": data}, fh, ensure_ascii=False)
        except (OSError, TypeError):
            pass

    def is_expired(self, provider: str, key: str) -> bool:
        return self.get(provider, key) is None
