"""Normalization helpers: domains, hostnames, deduplication."""

from __future__ import annotations

import re
from typing import Iterable


def normalize_hostname(name: str) -> str:
    """Lowercase, strip wildcard prefix, trailing dot, whitespace."""
    n = (name or "").strip().lower().rstrip(".")
    n = n.lstrip("*").lstrip(".")
    return n


def normalize_domain_set(names: Iterable[str]) -> set[str]:
    """Deduplicated, lowercase hostnames; drops empties and non-host entries."""
    out: set[str] = set()
    for raw in names:
        n = normalize_hostname(raw)
        if n and re.match(r"^[a-z0-9][a-z0-9.-]*$", n):
            out.add(n)
    return out


def dedupe_ordered(items: Iterable[str]) -> list[str]:
    """Remove duplicates while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def is_subdomain_of(candidate: str, parent: str) -> bool:
    c, p = normalize_hostname(candidate), normalize_hostname(parent)
    return c == p or c.endswith("." + p)


def classify_subdomain_label(subdomain: str) -> str:
    """Classify by the leftmost label. Purely descriptive — never a vuln label."""
    left = normalize_hostname(subdomain).split(".")[0]
    mapping = {
        "www": "web", "web": "web", "m": "mobile-web",
        "mail": "mail", "webmail": "mail", "smtp": "mail", "owa": "mail",
        "api": "api", "gateway": "api",
        "portal": "portal", "vpn": "vpn", "remote": "vpn",
        "dev": "development", "test": "testing", "staging": "staging",
        "uat": "staging", "demo": "staging",
        "admin": "administration", "cpanel": "administration",
        "cdn": "cdn", "static": "cdn", "assets": "cdn",
        "ns1": "nameserver", "ns2": "nameserver", "dns": "nameserver",
        "ftp": "file-transfer", "backup": "backup",
        "git": "devops", "jenkins": "devops", "ci": "devops",
        "erp": "business-app", "hr": "business-app", "crm": "business-app",
    }
    return mapping.get(left, "other")
