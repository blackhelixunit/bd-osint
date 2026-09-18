"""Configuration loading (config.yaml + CLI overrides)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "general": {"timeout": 15, "concurrency": 5, "cache_ttl": 86400},
    "rate_limits": {"default_delay": 1.5, "gov_bd_delay": 3.0},
    "providers": {"crtsh": True, "wayback": True, "rdap": True},
    "authorized": {"enabled": False},
    "cache": {"directory": "cache"},
}

CONFIG_SEARCH_PATHS = ("config.yaml", "config.yml", "~/.bdosint/config.yaml")


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load YAML config merged over DEFAULTS. Missing file -> defaults."""
    cfg = _deep_copy(DEFAULTS)
    candidates = [path] if path else list(CONFIG_SEARCH_PATHS)
    for cand in candidates:
        if not cand:
            continue
        full = Path(os.path.expanduser(cand))
        if full.is_file():
            try:
                with full.open("r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                _merge(cfg, data)
            except (yaml.YAMLError, OSError) as exc:
                print(f"[!] config load failed ({cand}): {exc}")
            break
    return cfg


def _deep_copy(d: dict[str, Any]) -> dict[str, Any]:
    return {k: _deep_copy(v) if isinstance(v, dict) else v for k, v in d.items()}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
