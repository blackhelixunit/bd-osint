"""Subdomain aggregation and classification from passive sources."""

from __future__ import annotations

import logging
from typing import Any

from bdosint.core.normalization import (
    classify_subdomain_label,
    is_subdomain_of,
    normalize_domain_set,
)

log = logging.getLogger("bdosint")


def aggregate(domain: str, dns: dict, crtsh: dict, shodan_subs: list[str] | None = None) -> dict[str, Any]:
    """Combine CT names + DNS observations + optional APIs. Deduplicated.

    IMPORTANT: labels like 'admin'/'dev'/'test' describe function only.
    They are NEVER treated as vulnerability indicators.
    """
    candidates: set[str] = set()
    candidates |= normalize_domain_set(crtsh.get("names", []))
    for rtype in ("A", "AAAA", "CNAME", "MX", "NS"):
        for value in dns.get(rtype, []):
            host = value.split()[-1] if rtype == "MX" else value
            s = normalize_domain_set([host])
            host = next(iter(s)) if s else ""
            if host and is_subdomain_of(host, domain):
                candidates.add(host)
    for sub in shodan_subs or []:
        full = f"{str(sub).strip().lower()}.{domain}"
        if is_subdomain_of(full, domain):
            candidates.add(full)
    candidates.add(domain)

    results = []
    for sub in sorted(candidates):
        results.append({
            "subdomain": sub,
            "label": sub.split(".")[0],
            "classification": classify_subdomain_label(sub),
            "source": "passive aggregation",
        })
    return {"domain": domain, "count": len(results), "subdomains": results}
