"""OPTIONAL Shodan integration (paid API key required; core tool never needs it)."""

from __future__ import annotations

import logging

log = logging.getLogger("bdosint")


def subdomains(domain: str, api_key: str, http) -> list[str]:
    """Fetch observed subdomains from Shodan. Returns [] on any failure."""
    data, err = http.get_json(f"https://api.shodan.io/dns/domain/{domain}",
                              provider="shodan", params={"key": api_key})
    if err:
        log.warning(f"shodan (optional): {err}")
        return []
    return data.get("subdomains", []) if isinstance(data, dict) else []
