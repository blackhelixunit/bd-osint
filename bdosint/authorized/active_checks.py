"""AUTHORIZED-ONLY active checks (DNS AXFR, ports). Gated by profile."""

from __future__ import annotations

import logging
from typing import Any

from bdosint.authorized.nmap_scan import AUTHORIZATION_BANNER, scan as nmap_scan
from bdosint.passive.dns import collect_zone_transfer

log = logging.getLogger("bdosint")


def run(profile: str, domain: str, modules: set[str],
        ports: str, timeout: float) -> dict[str, Any]:
    """Execute authorized checks. Hard-fails unless profile == 'authorized'."""
    if profile != "authorized":
        raise PermissionError(
            "Active checks require --profile authorized. "
            "Refusing to run active scanning without explicit authorized profile."
        )
    log.warning(AUTHORIZATION_BANNER)
    results: dict[str, Any] = {}
    if "ports" in modules:
        log.info("Authorized port scan (nmap, conservative)")
        results["ports"] = nmap_scan(domain, ports=ports, timeout=timeout)
    if "axfr" in modules:
        log.info("Authorized DNS zone transfer attempt")
        results["zone_transfer"] = collect_zone_transfer(domain, timeout=timeout)
    return results
